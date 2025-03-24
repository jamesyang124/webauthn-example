import { useState } from 'react';
import reactLogo from './assets/react.svg';
import viteLogo from '/vite.svg';
import './App.css';
import { Button, Card, Typography, Box, TextField } from '@mui/material';
import {
  RegistrationResponseData,
  CredentialCreationOptions,
  AuthenticationResponseData,
} from './webauthn';

function base64UrlToBase64Std(baseText: string): string {
  return baseText.replace(/-/g, "+").replace(/_/g, "/");
};

function base64StdToArrayBuffers(baseText: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(baseText), c => c.charCodeAt(0));
};

const handleWebAuthnLogin = async (responseData: AuthenticationResponseData, username: string) => {
  try {
    const challenge = base64UrlToBase64Std(responseData.publicKey.challenge);
    const allowCredentials = responseData.publicKey.allowCredentials?.map(cred => ({
      type: 'public-key' as const,
      id: base64StdToArrayBuffers(base64UrlToBase64Std(cred.id))
    }));
    const options: CredentialRequestOptions = {
      publicKey: {
        ...responseData.publicKey,
        challenge: base64StdToArrayBuffers(challenge),
        allowCredentials
      },
    };
  
    const assertionResponse = await navigator.credentials.get(options);
    console.log('authentication assertionResponse', assertionResponse);

    const payload = {
      credential: assertionResponse,
      username: username
    };

    const response = await fetch(`${import.meta.env.VITE_API_URL}/webauthn/authenticate/verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      mode: 'cors', // Added to avoid CORS issues
    });

    const verificationResponse = await response.json();
    console.log('Authentication verification response:', verificationResponse);

    if (response.ok) {
      alert('Authentication verified successfully!');
    } else {
      alert('Authentication verification failed.');
    }
  } catch (error) {
    console.error('Error during authentication verification:', error);
    alert('An error occurred during authentication verification. Please try again.');
  }
};

const handleWebAuthnRegistration = async (responseData: RegistrationResponseData) => {
  console.log(responseData);

  try {
    const challenge = base64UrlToBase64Std(responseData.publicKey.challenge);
    const userId = responseData.publicKey.user.id;
    const options: CredentialCreationOptions = {
      publicKey: {
        ...responseData.publicKey,
        challenge: base64StdToArrayBuffers(challenge),
        user: {
          ...responseData.publicKey.user,
          id: base64StdToArrayBuffers(userId),
        },
      },
    };

    const credential = await navigator.credentials.create(options);
    console.log(credential);

    const payload = {
      credential,
      username: options.publicKey.user.name,
      displayname: options.publicKey.user.displayName,
    };

    const response = await fetch(`${import.meta.env.VITE_API_URL}/webauthn/register/verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      mode: 'cors', // Added to avoid CORS issues
    });

    const verificationResponse = await response.json();
    console.log('Registration verification response:', verificationResponse);

    if (response.ok) {
      alert('Registration successful!');
    } else {
      alert('Registration failed.');
    }
  } catch (error) {
    console.error('Error during registration:', error);
  }
};

const registerClick = async (username: string) => {
  try {
    if (!username) {
      alert('Please enter a username.');
      return;
    }
    console.log('Registration options ajax request in:');
    const response = await fetch(`${import.meta.env.VITE_API_URL}/webauthn/register/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ "username": username }),
      mode: 'cors', // Added to avoid CORS issues
    });
    if (!response.ok) {
      throw new Error(`Registration failed: ${response.statusText}`);
    }

    const responseData: RegistrationResponseData = await response.json();
    console.log('Registration response:', responseData);
    await handleWebAuthnRegistration(responseData);
  } catch (error) {
    console.error('Error during registration:', error);
    alert('An error occurred during registration. Please try again.');
  }
};

const authenticateClick = async (username: string) => {
  try {
    if (!username) {
      alert('Please enter a username.');
      return;
    }
    const response = await fetch(`${import.meta.env.VITE_API_URL}/webauthn/authenticate/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ "username": username }),
      mode: 'cors', // Added to avoid CORS issues
    });
    const responseData: AuthenticationResponseData = await response.json();
    console.log('Authentication response:', responseData);

    handleWebAuthnLogin(responseData, username);
  } catch (error) {
    console.error('Error during authentication:', error);
  }
};

function App() {
  const [registerUsername, setRegisterUsername] = useState('user1');
  const [authenticateUsername, setAuthenticateUsername] = useState('user1');

  return (
    <Box sx={{ textAlign: 'center', padding: 2 }}>
      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, marginBottom: 2 }}>
        <a href="https://vite.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </Box>
      <Typography variant="h4" gutterBottom>
        Webauthn Example
      </Typography>
      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, marginBottom: 2 }}>
        <Card sx={{ padding: 2, width: '300px' }}>
          <TextField
            label="username"
            variant="outlined"
            value={registerUsername}
            onChange={(e) => setRegisterUsername(e.target.value)}
            fullWidth
            sx={{ marginBottom: 2 }}
          />
          <Button variant="contained" onClick={() => registerClick(registerUsername)}>
            Register
          </Button>
          <Typography variant="body1" sx={{ marginTop: 1 }}>
            Register by passkey for WebAuthn
          </Typography>
        </Card>
        <Card sx={{ padding: 2, width: '300px' }}>
          <TextField
            label="username"
            variant="outlined"
            value={authenticateUsername}
            onChange={(e) => setAuthenticateUsername(e.target.value)}
            fullWidth
            sx={{ marginBottom: 2 }}
          />
          <Button variant="contained" onClick={() => authenticateClick(authenticateUsername)}>
            Login
          </Button>
          <Typography variant="body1" sx={{ marginTop: 1 }}>
            Authenticate by passkey for WebAuthn
          </Typography>
        </Card>
      </Box>
    </Box>
  );
}

export default App;
