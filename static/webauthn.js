document.getElementById('register').addEventListener('click', async () => {
    try {
        const response = await fetch('/webauthn/register', { method: 'POST' });
        const options = await response.json();
        const credential = await navigator.credentials.create({ publicKey: options });
        const credentialResponse = {
            id: credential.id,
            rawId: arrayBufferToBase64(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: arrayBufferToBase64(credential.response.attestationObject),
                clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
            },
        };
        await fetch('/webauthn/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentialResponse),
        });
        alert('Registration successful');
    } catch (error) {
        console.error('Error during registration:', error);
    }
});

document.getElementById('authenticate').addEventListener('click', async () => {
    try {
        const response = await fetch('/webauthn/authenticate', { method: 'POST' });
        const options = await response.json();
        const assertion = await navigator.credentials.get({ publicKey: options });
        const assertionResponse = {
            id: assertion.id,
            rawId: arrayBufferToBase64(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: arrayBufferToBase64(assertion.response.authenticatorData),
                clientDataJSON: arrayBufferToBase64(assertion.response.clientDataJSON),
                signature: arrayBufferToBase64(assertion.response.signature),
                userHandle: arrayBufferToBase64(assertion.response.userHandle),
            },
        };
        await fetch('/webauthn/authenticate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(assertionResponse),
        });
        alert('Authentication successful');
    } catch (error) {
        console.error('Error during authentication:', error);
    }
});

function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
