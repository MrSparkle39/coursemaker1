function generateTTS(index) {
    const text = document.getElementById(`tts${index}`).value;
    if (!text.trim()) {
        alert('Please enter some text first!');
        return;
    }

    // Show loading state
    const button = event.target;
    const originalText = button.innerHTML;
    button.innerHTML = '⏳ Generating...';
    button.disabled = true;

    // Call your TTS backend
    fetch('/api/generate-tts', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            text: text,
            voice: 'en-US-Neural2-A',
            userId: 'demo-user',
            subscription: 'pro'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`✅ TTS Generated! Audio URL: ${data.audioUrl}\nCharacters used: ${data.charactersUsed}`);
            button.innerHTML = '✅ TTS Generated';
            button.style.background = '#28a745';
        } else {
            alert(`❌ Error: ${data.error}`);
            button.innerHTML = originalText;
        }
    })
    .catch(error => {
        alert(`❌ Connection Error: ${error.message}`);
        button.innerHTML = originalText;
    })
    .finally(() => {
        button.disabled = false;
    });
}

function testTTS() {
    alert('Testing direct TTS connection...');
    
    fetch('/api/generate-tts', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            text: 'Hello, this is a test of the Google Cloud Text to Speech integration!',
            voice: 'en-US-Neural2-A',
            userId: 'test-user',
            subscription: 'pro'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`🎉 TTS Backend Working!\n\nAudio URL: ${data.audioUrl}\nCharacters: ${data.charactersUsed}\n\nYour Google Cloud TTS is connected!`);
        } else {
            alert(`❌ TTS Error: ${data.error}`);
        }
    })
    .catch(error => {
        alert(`❌ Connection failed: ${error.message}`);
    });
}
