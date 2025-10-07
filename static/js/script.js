function showToast(message, type = 'info', persistent = false) {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        console.error('Toast container not found!');
        return;
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    let toastContent = `
    <div class="toast-content">${message}</div>
    <div class="toast-buttons">
    `;

    if (type === 'unsaved' && typeof userRole !== 'undefined' && userRole === 'admin') {
    toastContent += `
        <button onclick="discardChanges()">Revert</button>
        <button onclick="saveChanges()" style="background-color: #28a745; color: white;">Save</button>
    `;
    }

    toastContent += `</div><button class="toast-close-button">&times;</button>`;
    toast.innerHTML = toastContent;

    const closeButton = toast.querySelector('.toast-close-button');
    let timeoutId = null;

    function closeToast() {
        toast.style.animation = 'slideOut 0.5s ease-out forwards';
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
            if(timeoutId) clearTimeout(timeoutId);
        }, 500);
    }

    closeButton.addEventListener('click', closeToast);

    if (!persistent) {
      timeoutId = setTimeout(closeToast, 5000);
    }

    toastContainer.appendChild(toast);
    return toast;
}

// Backend Connection Status Checker
document.addEventListener('DOMContentLoaded', () => {
    let connectionLostToast = null;
    let isConnected = true;

    function checkConnection() {
        fetch('/health')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Backend not reachable');
                }
                return response.json();
            })
            .then(data => {
                if (data.status === 'ok' && !isConnected) {
                    isConnected = true;
                    if (connectionLostToast) {
                        // Manually close the persistent "lost connection" toast
                        connectionLostToast.style.animation = 'slideOut 0.5s ease-out forwards';
                        setTimeout(() => {
                            if (connectionLostToast.parentNode) {
                                connectionLostToast.parentNode.removeChild(connectionLostToast);
                            }
                            connectionLostToast = null;
                        }, 500);
                    }
                    showToast('Connection re-established.', 'success');
                }
            })
            .catch(() => {
                if (isConnected) {
                    isConnected = false;
                    // Show a persistent toast
                    connectionLostToast = showToast('Connection to server lost. Trying to reconnect...', 'error', true);
                }
            });
    }

    setInterval(checkConnection, 5000);
});