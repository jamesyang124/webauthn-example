import {
  RegistrationResponseData,
  CredentialCreationOptions,
  AuthenticationResponseData,
} from './types/webauthn';

import AuthPage from './components/auth/AuthPage';

function base64UrlToBase64Std(baseText: string): string {
  return baseText.replace(/-/g, "+").replace(/_/g, "/");
};

function base64StdToArrayBuffers(baseText: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(baseText), c => c.charCodeAt(0));
};




//  const [registerUsername, setRegisterUsername] = useState('user1');
//  const [authenticateUsername, setAuthenticateUsername] = useState('user1');

function App() {
  return (
    <div className="app">
      <AuthPage />
    </div>
  );
}

export default App;
