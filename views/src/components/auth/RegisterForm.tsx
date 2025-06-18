import { useState } from 'react';
import { RegisterFormData } from 'auth';
import { base64UrlToBase64Std, base64StdToArrayBuffers } from '../../utils';
import {
  RegistrationResponseData,
  CredentialCreationOptions
} from 'webauthn';

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

    // Create WebAuthn credential using browser API
    const credential = await navigator.credentials.create(options);
    console.log(credential);

    const payload = {
      credential,
      username: options.publicKey.user.name,
      displayname: options.publicKey.user.displayName,
    };

    // Send credential to server for verification
    const response = await fetch(`${import.meta.env.VITE_API_URL}/webauthn/register/verification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      mode: 'cors', // Added to avoid CORS issues
    });

    // Parse server response
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

const handleRegistrationFlow = async (username: string) => {
  try {
    if (!username) {
      alert('Please enter a username.');
      return;
    }
    console.log('Registration options ajax request in:');
    // Request registration options from server
    const response = await fetch(`${import.meta.env.VITE_API_URL}/webauthn/register/options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ "username": username }),
      mode: 'cors', // Added to avoid CORS issues
    });
    if (!response.ok) {
      throw new Error(`Registration failed: ${response.statusText}`);
    }

    // Parse registration options response
    const responseData: RegistrationResponseData = await response.json();
    console.log('Registration response:', responseData);
    // Process WebAuthn registration with received options
    await handleWebAuthnRegistration(responseData);
  } catch (error) {
    console.error('Error during registration:', error);
    alert('An error occurred during registration. Please try again.');
  }
};


const RegisterForm = () => {
  const [formData, setFormData] = useState<RegisterFormData>({
    username: 'user1',
  });
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Partial<RegisterFormData>>({});

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));

    // Clear error when user types
    if (errors[name as keyof RegisterFormData]) {
      setErrors((prev) => ({
        ...prev,
        [name]: '',
      }));
    }
  };

  const validateForm = (): boolean => {
    const newErrors: Partial<RegisterFormData> = {};

    if (!formData.username.trim()) {
      newErrors.username = 'Username is required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setLoading(true);

    // Execute complete registration flow
    await handleRegistrationFlow(formData.username);

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
            className={`block w-full appearance-none rounded-md border ${errors.username ? 'border-red-300' : 'border-gray-300'
              } px-3 py-2 placeholder-gray-400 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm`}
            placeholder="Enter passkey's username"
            value={formData.username}
            onChange={handleChange}
          />
          {errors.username && (
            <p className="mt-1 text-sm text-red-600">{errors.username}</p>
          )}
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
          {loading ? 'Creating account...' : 'Create account'}
        </button>
      </div>
    </form>
  );
};

export default RegisterForm;
