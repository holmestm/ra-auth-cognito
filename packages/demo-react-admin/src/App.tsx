import React from 'react';
import { Admin, Resource, CustomRoutes, NotFound } from 'react-admin';
import { BrowserRouter, Route } from 'react-router-dom';
import comments from './comments';
import CustomRouteLayout from './customRouteLayout';
import CustomRouteNoLayout from './customRouteNoLayout';
import i18nProvider from './i18nProvider';
import Layout from './Layout';
import posts from './posts';
import users from './users';
import tags from './tags';
import { CognitoAuthProvider, Login } from 'ra-auth-cognito';
import fakeRestProvider from 'ra-data-fakerest';
import { CognitoUserPool } from 'amazon-cognito-identity-js';
import data from './data';

const userPool = new CognitoUserPool({
    UserPoolId: import.meta.env.VITE_COGNITO_USERPOOL_ID,
    ClientId: import.meta.env.VITE_COGNITO_APP_CLIENT_ID,
});

// const authProvider = CognitoAuthProvider(userPool);
// To test the oauth mode
const authProvider = CognitoAuthProvider({
    mode: import.meta.env.VITE_COGNITO_MODE,
    hostedUIUrl: import.meta.env.VITE_COGNITO_HOSTED_UI_URL,
    userPoolId: import.meta.env.VITE_COGNITO_USERPOOL_ID,
    clientId: import.meta.env.VITE_COGNITO_APP_CLIENT_ID,
    oauthGrantType: import.meta.env.VITE_COGNITO_OAUTH_MODE,
    redirect_uri: `${window.location.origin}/${import.meta.env.VITE_COGNITO_REDIRECT_URI}`,
    scope: ['openid', 'email', 'profile', 'aws.cognito.signin.user.admin'],
});

const App = () => {
    return (
        <BrowserRouter>
            <Admin
                authProvider={authProvider}
                dataProvider={fakeRestProvider(data)}
                i18nProvider={i18nProvider}
                title="Example Admin"
                layout={Layout}
                loginPage={authProvider.mode === 'username' ? Login : false}
            >
                <Resource name="posts" {...posts} />
                <Resource name="comments" {...comments} />
                <Resource name="users" {...users} />
                <Resource name="tags" {...tags} />
            </Admin>
        </BrowserRouter>
    );
};
export default App;
