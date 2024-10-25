![bin-chan](https://github.com/PolishTanker/bin/blob/main/static/images/logo.svg?raw=true)

# Bin-chan: A Temporary Text Sharing Web Application

## Overview

Bin-chan is a lightweight web application for securely sharing text snippets with an expiration time. Users can submit a piece of text, set an expiry time with password, and share a unique URL to access the text before it expires. After the set expiry time, the text is automatically deleted. This makes Bin-chan an ideal solution for sharing temporary or sensitive information.

## Features

1. **Temporary Text Sharing**: Users can submit and share text that will automatically expire after a set period (1 hour, 3 hours, 24 hours, or 7 days).
2. **Custom URLs**: Users can optionally create a custom URL up to 40 characters for the text they submit. If no custom URL is provided, a random 8-character string is generated.
3. **Text Size Limit**: Text submissions are limited to 6000 characters.
4. **Automatic Expiry**: Text is automatically deleted from the database after its expiration time.
5. **Alternate Endpoint**: Users can get the content of the share as plain text for cli aplications. Link changes to https://example.com/text/sharename 
6. **Password Lock and Encryption in Database**: Users can lock share with password. Additionaly it will be encrypted in database, in this way it will not be redable for server admin. Users can pass password in curl if they need it in cli with header, like this: curl -H "pswd: password" https://example.com/text/sharename

### Prerequisites

Make sure you have the following installed on your system:
- Python 3.x
- SQLite (for local database storage)
