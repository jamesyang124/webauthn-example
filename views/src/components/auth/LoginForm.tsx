import { useState } from 'react';
import { LoginFormData } from '../../types/auth';
import { AuthenticationResponseData } from '../../types/webauthn';
import { base64UrlToBase64Std, base64StdToArrayBuffers } from '../../utils';

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

const handleLoginFlow = async (username: string) => {
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

const LoginForm = () => {
  const [formData, setFormData] = useState<LoginFormData>({
    username: 'user1',
  });
  const [loading, setLoading] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    await handleLoginFlow(formData.username);

    setLoading(false);
  };

  return (
    <form className="space-y-6" onSubmit={handleSubmit}>
      <div>
        <label htmlFor="username" className="block text-sm font-medium text-gray-700">
          Passkey's user name
        </label>
        <div className="mt-1">
          <input
            id="username"
            name="username"
            type="text"
            autoComplete="username"
            required
            className={`block w-full appearance-none rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm`}
            placeholder="Enter passkey's username"
            value={formData.username}
            onChange={handleChange}
          />
        </div>
      </div>


      <div>
        <button
          type="submit"
          disabled={loading}
          className={`group relative flex w-full justify-center rounded-md border border-transparent py-2 px-4 text-sm font-medium text-white ${loading
            ? 'bg-indigo-400 cursor-not-allowed'
            : 'bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2'
            }`}
        >
          {loading ? 'Signing in...' : 'Sign in'}
        </button>
      </div>
    </form>
  );
};

export default LoginForm;
