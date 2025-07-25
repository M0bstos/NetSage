# NetSage Frontend

This directory contains the frontend code for the NetSage application.

## Directory Structure

```
frontend/
├── css/               # Contains all styling files
│   └── style.css      # Main stylesheet
├── images/            # Image assets
│   ├── full-image.png
│   ├── img1.png
│   ├── img2.png
│   ├── img3.png
│   └── img4.png
├── js/                # JavaScript files
│   └── script.js      # Main JavaScript file
└── index.html         # Main HTML file
```

## Development

To run the frontend locally, simply open the `index.html` file in a web browser.

## Integration with Backend

The frontend interacts with the backend through API endpoints and webhooks. The main interaction points are:

- Website scanning via the n8n webhook at `http://localhost:5678/webhook-test/scan-website`
- Retrieving scan reports and results

For more details on API integration, refer to the integration guide in the root directory.
