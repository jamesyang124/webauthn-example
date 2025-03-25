import webauthnLogo from '../../../public/shield.svg';

const AuthPageIcon = () => {
  return (
    <div className="flex justify-center">
      <img
        src={webauthnLogo}
        alt="WebAuthn Shield Icon"
        className="h-56 w-56"
      />
    </div>
  );
};

export default AuthPageIcon;