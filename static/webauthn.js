document.getElementById('register').addEventListener('click', async () => {
    try {
        const username = document.getElementById('username').value;
        if (!username) {
            alert('Please enter a username.');
            return;
        }
        console.log('Registration options ajax request in:');
        const response = await fetch('/webauthn/register/options', {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ "username": username }), 
        });
        if (!response.ok) {
            throw new Error(`Registration failed: ${response.statusText}`);
        }
        const responseData = await response.json();
        console.log('Registration response:', responseData);
        await handleWebAuthnRegistration(responseData);
    } catch (error) {
        console.error('Error during registration:', error);
        alert('An error occurred during registration. Please try again.');
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

async function handleWebAuthnRegistration(options) {
    console.log(options);
    const challenge = options.publicKey.challenge.replace(/-/g, "+").replace(/_/g, "/");
    const userId = options.publicKey.user.id;

    try {
        options.publicKey.challenge = Uint8Array.from(atob(challenge), c => c.charCodeAt(0));
        options.publicKey.user.id = Uint8Array.from(atob(userId), c => c.charCodeAt(0));
    } catch (e) {
        console.error('Error decoding base64 string:', e);
        return;
    }

    try {
        const credential = await navigator.credentials.create({ publicKey: options.publicKey });
        console.log(credential);

        const payload = {
            "credential": credential,
            "username": options.publicKey.user.name,
            "displayname": options.publicKey.user.displayName
        };

        const response = await fetch('/webauthn/register/verification', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            alert('Registration successful!');
        } else {
            alert('Registration failed.');
        }
    } catch (error) {
        console.error('Error during registration:', error);
    }
}

function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
