import { CognitoAuthProviderOptionsIds } from "../authProvider"
import { pkceUtils } from "./pkceUtils";
import { CognitoUserSession, CognitoIdToken, CognitoRefreshToken, CognitoAccessToken, CognitoUser, CognitoUserPool } from "amazon-cognito-identity-js";
import logger from "./logger";

export const revokeTokens = async (options: CognitoAuthProviderOptionsIds) => {
  const { hostedUIUrl, clientId } = options;
  try {
    const auth = JSON.parse(localStorage.getItem('auth') || '{}');
    const accessToken = auth?.access_token;

    if (!accessToken) {
      return;
    }

    // Call the revoke endpoint
    const revokeEndpoint = new URL(`${hostedUIUrl!.replace('/login', '')}/oauth2/revoke`);
    const response = await fetch(revokeEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        token: accessToken,
        clientId,
      }),
    });
    logger.info('Response from revoke endpoint:', response);
  } catch (error) {
    logger.error('Error revoking tokens:', error);
  }
};

export const clearLocalStorage = () => {
  // Clear all auth-related items from localStorage
  localStorage.removeItem('auth');
  localStorage.removeItem('CognitoIdentityServiceProvider');
  sessionStorage.removeItem('pkce_code_verifier');
  for (const key in localStorage) {
    if (key.startsWith('CognitoIdentityServiceProvider.')) {
      localStorage.removeItem(key);
    }
  }

  // Clear any other auth-related cookies
  document.cookie.split(';').forEach(cookie => {
    const [name] = cookie.split('=');
    document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/`;
  });
};

export const cognitoLogout = async (options: CognitoAuthProviderOptionsIds) => {
  const { hostedUIUrl, clientId } = options;
  try {
    logger.info('Cognito Logout called:');
    // Get current auth state
    const auth = JSON.parse(localStorage.getItem('auth') || '{}');

    // Construct logout URL with all necessary parameters
    const logoutUrl = new URL(`${hostedUIUrl!.replace('/login', '')}/logout`);
    logoutUrl.searchParams.append('client_id', clientId!);
    logoutUrl.searchParams.append('logout_uri', `${window.location.origin}/`);

    // If using SAML or social providers, add additional parameters
    if (auth.id_token) {
      logoutUrl.searchParams.append('id_token_hint', auth.id_token);
    }

    // Clear local storage before redirect
    clearLocalStorage();

    // First revoke the tokens
    await revokeTokens(options);
    logger.info('Revoke tokens called, redirecting to:', logoutUrl.toString());

    // Wait for all cleanup operations to complete
    await new Promise(resolve => setTimeout(resolve, 100));

    // Redirect to Cognito logout
    return logoutUrl.toString();

  } catch (error) {
    logger.error('Error during logout:', error);
    console.trace();
    // Even if there's an error, clear local storage
    clearLocalStorage();
    window.location.href = `${window.location.origin}/`;
  }
};

export const pkceCognitoLogin = async (currentUrl: string, options: CognitoAuthProviderOptionsIds) => {
  logger.info('PKCE Login called:')
  try {
    // Generate PKCE values
    const codeVerifier = pkceUtils.generateCodeVerifier();
    const codeChallenge = await pkceUtils.generateCodeChallenge(codeVerifier);

    logger.info('Setting code verifier:', codeVerifier);
    logger.info('Setting code challenge:', codeChallenge);

    // Store code verifier in session storage
    sessionStorage.setItem('pkce_code_verifier', codeVerifier);

    // try and send the user back to the page they were on once we have logged them in
    localStorage.setItem('currentUrl', currentUrl);

    // Construct authorization URL with PKCE
    const authorizationUrl = new URL(`${options.hostedUIUrl}/oauth2/authorize`);
    authorizationUrl.searchParams.append('client_id', options.clientId!);
    authorizationUrl.searchParams.append('response_type', 'code');
    authorizationUrl.searchParams.append('scope', options.scope!.join(' '));
    authorizationUrl.searchParams.append('redirect_uri', options.redirect_uri!);
    authorizationUrl.searchParams.append('code_challenge', codeChallenge);
    authorizationUrl.searchParams.append('code_challenge_method', 'S256');

    // Redirect to Cognito hosted UI
    window.location.href = authorizationUrl.toString();
  } catch (error) {
    logger.error('Error during PKCE login:', error);
  }
};

export const resolveTokens = async (code: string, options: CognitoAuthProviderOptionsIds) => {

  // Retrieve code verifier
  const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
  if (!codeVerifier) {
    throw new Error('No code verifier found');
  }

  logger.info('Exchanging code with verifier:', codeVerifier);
  logger.info('Received code:', code);
  // Exchange code for tokens
  const tokenEndpoint = `${options.hostedUIUrl!.replace('/login', '')}/oauth2/token`;
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: options.clientId!,
      code_verifier: codeVerifier!,
      code: code!,
      redirect_uri: options.redirect_uri!,
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to exchange code for tokens');
  }

  const tokens = await response.json();

  logger.info('Received tokens:', tokens);
  return tokens;
}

export const refreshToken = async (options: CognitoAuthProviderOptionsIds) => {
  try {
    const auth = JSON.parse(localStorage.getItem('auth') || '{}');
    const refreshToken = auth.refresh_token;

    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const tokenEndpoint = `${options.hostedUIUrl!.replace('/login', '')}/oauth2/token`;
    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: options.clientId,
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to refresh tokens');
    }

    const tokens = await response.json();

    // Update stored tokens
    localStorage.setItem('auth', JSON.stringify({
      ...auth,
      access_token: tokens.access_token,
      id_token: tokens.id_token,
    }));

    return Promise.resolve();
  } catch (error) {
    return Promise.reject(error);
  }
}

export interface CognitoTokens {
  id_token: string;
  refresh_token: string;
  accessToken: string;
}

export const createCognitoSession = (
  tokens: CognitoTokens,
  userPool: CognitoUserPool
): CognitoUser => {
  // Create Cognito User and Session
  const session = new CognitoUserSession({
    IdToken: new CognitoIdToken({ IdToken: tokens.id_token }),
    RefreshToken: new CognitoRefreshToken({ RefreshToken: tokens.refresh_token }),
    AccessToken: new CognitoAccessToken({ AccessToken: tokens.accessToken }),
  });
  const user = new CognitoUser({
    Username: session.getIdToken().decodePayload()['cognito:username'],
    Pool: userPool,
    Storage: window.localStorage,
  });
  user.setSignInUserSession(session);
  return user;
};

export const codeCognitoCallback = async (userPool: CognitoUserPool, options: CognitoAuthProviderOptionsIds) => {
  try {
    const url = new URL(window.location.href);
    const code = url.searchParams.get('code');
    if (!code) {
      throw new Error('No authorization code in callback URL');
    }

    const tokens: CognitoTokens = await resolveTokens(code, options);

    // Store tokens
    localStorage.setItem('auth', JSON.stringify(tokens));

    // Clean up code verifier
    sessionStorage.removeItem('pkce_code_verifier');

    const user = createCognitoSession(tokens, userPool);

    logger.info('User Object Created:', user);

    // Redirect to admin panel
    return user;
  } catch (error) {
    return Promise.reject(error);
  }
}