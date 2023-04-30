// Add a click event listener to the document

const analyticsServerURL = '{{analyticsServerURL}}';

document.addEventListener('click', event => {


    // Create a data object with information about the click
    const data = {
        type: 'click',
        tag: event.target.tagName,
        url: event.target.href || event.target.src,
        text: event.target.textContent || event.target.innerText || event.target.alt || event.target.title,
        timestamp: Date.now()
    };

    // Send the data to the server
    fetch(analyticsServerURL, {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json'
        }
    })
        .then(response => {
            // Handle the server response here
            console.log('Analytics data sent:', data);
        })
        .catch(error => {
            // Handle errors here
            console.error('Failed to send analytics data:', error);
        });

});
