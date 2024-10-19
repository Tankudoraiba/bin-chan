![bin-chan](https://github.com/PolishTanker/bin/blob/main/static/images/logo.svg?raw=true)

# Bin-chan: A Temporary Text Sharing Web Application

## Overview

Bin-chan is a lightweight web application for securely sharing text snippets with an expiration time. Users can submit a piece of text, set an expiry time, and share a unique URL to access the text before it expires. After the set expiry time, the text is automatically deleted. This makes Bin-chan an ideal solution for sharing temporary or sensitive information.

## Features

1. **Temporary Text Sharing**: Users can submit and share text that will automatically expire after a set period (1 hour, 3 hours, 24 hours, or 7 days).
2. **Custom URLs**: Users can optionally create a custom URL for the text they submit. If no custom URL is provided, a random 8-character string is generated.
3. **Text Size Limit**: Text submissions are limited to 6000 characters.
4. **Automatic Expiry**: Text is automatically deleted from the database after its expiration time.
5. **Alternate endpoint**: You can get the content of the share as plain text for cli aplications. Link changes to http://example.com/text/sharename 

## How to Use the Bin-chan Website

1. **Home Page**:
   - Upon loading the page, you'll see a simple form where you can enter your text.
   - You can optionally specify a custom URL (this will be part of the link to access the text).
   - Select the expiry time for the text (1 hour, 3 hours, 24 hours, or 7 days).
   - Click the "Share Text" button to generate a unique URL for the text.
   - If successful, you will be redirected to the page with your text.

2. **Sharing the Link**:
   - After submitting the text, a unique URL will be generated.
   - This link can be copied and shared with others. Anyone with the link can view the text until it expires.

3. **Viewing and Interacting with the Text**:
   - When visiting a shared URL, the text will be displayed on a clean page.
   - You have the option to copy the text or the URL with a single click.
   - The link will expire after the designated time and can no longer be accessed once expired.

### Prerequisites

Make sure you have the following installed on your system:
- Python 3.x
- SQLite (for local database storage)
- Flask (Python web framework)
