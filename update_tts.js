function generateTTS(index) {
    const text = document.getElementById(`tts${index}`).value;
    if (!text.trim()) {
        alert('Please enter some text first!');
        return;
    }

    // Show voice selection dialog
    const voices = [
        { value: 'en-US-Neural2-A', name: 'Emma (US Female) - $16/1M chars', cost: 16 },
        { value: 'en-US-Neural2-C', name: 'David (US Male) - $16/1M chars', cost: 16 },
        { value: 'en-US-Neural2-D', name: 'Jenny (US Female) - $16/1M chars', cost: 16 },
        { value: 'en-US-Neural2-F', name: 'Noah (US Male) - $16/1M chars', cost: 16 },
        { value: 'en-GB-Neural2-A', name: 'British Female - $16/1M chars', cost: 16 },
        { value: 'en-GB-Neural2-B', name: 'British Male - $16/1M chars', cost: 16 },
        { value: 'en-AU-Neural2-A', name: 'Australian Female - $16/1M chars', cost: 16 },
        { value: 'en-AU-Neural2-B', name: 'Australian Male - $16/1M chars', cost: 16 }
    ];

    let voiceOptions = voices.map((v, i) => `${i + 1}. ${v.name}`).join('\n');
    let choice = prompt(`Choose a voice (1-${voices.length}):\n\n${voiceOptions}\n\nEnter number (1-${voices.length}):`);
    
    if (!choice || choice < 1 || choice > voices.length) {
        alert('Invalid choice or cancelled');
        return;
    }

    const selectedVoice = voices[choice - 1];
    const estimatedCost = ((text.length / 1000000) * selectedVoice.cost).toFixed(4);
    
    if (!confirm(`Generate TTS with ${selectedVoice.name}?\n\nText length: ${text.length} characters\nEstimated cost: $${estimatedCost}\n\nContinue?`)) {
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
            voice: selectedVoice.value,
            userId: 'demo-user',
            subscription: 'pro'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`✅ TTS Generated!\n\nVoice: ${selectedVoice.name}\nAudio URL: ${data.audioUrl}\nCharacters used: ${data.charactersUsed}\nActual cost: $${((data.charactersUsed / 1000000) * selectedVoice.cost).toFixed(4)}`);
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
    alert('Testing TTS with cost-effective Neural2 voice...');
    
    fetch('/api/generate-tts', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            text: 'Hello, this is a test using only cost-effective Neural2 voices at sixteen dollars per million characters.',
            voice: 'en-US-Neural2-A',
            userId: 'test-user', 
            subscription: 'pro'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`🎉 TTS Backend Working!\n\nVoice: Neural2-A (Cost-effective)\nAudio URL: ${data.audioUrl}\nCharacters: ${data.charactersUsed}\nCost: $${((data.charactersUsed / 1000000) * 16).toFixed(4)}\n\nYour Google Cloud TTS is connected!`);
        } else {
            alert(`❌ TTS Error: ${data.error}`);
        }
    })
    .catch(error => {
        alert(`❌ Connection failed: ${error.message}`);
    });
}
