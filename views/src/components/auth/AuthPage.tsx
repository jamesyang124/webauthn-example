import { useState } from 'react';
import LoginForm from './LoginForm';
import RegisterForm from './RegisterForm';
import AuthPageIcon from './AuthPageIcon';

const AuthPage = () => {
  const [activeTab, setActiveTab] = useState<'login' | 'register'>('login');

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4 py-12 sm:px-6 lg:px-8">
      <div className="w-full max-w-md space-y-8">
        <AuthPageIcon />
        <div className="text-center">
          <h2 className="mt-6 text-3xl font-extrabold text-gray-900">
            Welcome to Webauthn Example
          </h2>
          <p className="mt-2 text-sm text-gray-600">
            {activeTab === 'login'
              ? 'Login by username and passkey'
              : 'Create your account by username and passkey'}
          </p>
        </div>

        <div className="mt-8">
          {/* Tabs for switching between login and register */}
          <div className="flex rounded-md shadow-sm">
            <button
              type="button"
              className={`w-1/2 rounded-l-md px-4 py-2 text-sm font-medium ${
                activeTab === 'login'
                  ? 'bg-indigo-600 text-white'
                  : 'bg-white text-gray-700 hover:bg-gray-50'
              }`}
              onClick={() => setActiveTab('login')}
            >
              Login
            </button>
            <button
              type="button"
              className={`w-1/2 rounded-r-md px-4 py-2 text-sm font-medium ${
                activeTab === 'register'
                  ? 'bg-indigo-600 text-white'
                  : 'bg-white text-gray-700 hover:bg-gray-50'
              }`}
              onClick={() => setActiveTab('register')}
            >
              Register
            </button>
          </div>

          {/* Form container */}
          <div className="mt-6">
            {activeTab === 'login' ? <LoginForm /> : <RegisterForm />}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuthPage;
