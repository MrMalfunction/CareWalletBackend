# CareWallet Cloud Assessment

A simple website for data collection and storage using AWS S3 and DynamoDB with session management.

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Technologies Used](#technologies-used)
4. [Setup and Installation](#setup-and-installation)
5. [Usage](#usage)
6. [Architecture](#architecture)
7. [Session Management](#session-management)
8. [Data Storage](#data-storage)
9. [Security Considerations](#security-considerations)
10. [License](#license)

## Overview

This project provides a basic website that allows users to log in or register, fill out, and submit forms, and view
previously submitted forms.

## Features

- **User Authentication**: Users can register or log in to the website. Resetting the password is also doable but
  restricted to verified email, due to AWS SES restriction.
- **Form Submission**: After logging in, users can fill out and submit forms.
- **View Submitted Forms**: Users can list and view previously submitted forms after logging in.
- **Session Management**: Sessions are created, validated, and expired using DynamoDB.

## Technologies Used

- **AWS S3**: Hosting the website (e.g., `index.html` page).
- **AWS DynamoDB**: Storing user data, form data, and session information.
- **HTML/CSS/JavaScript**: Frontend development.
- **AWS Lambda (optional)**: For backend processing (if needed).
- **AWS Cognito (optional)**: For user authentication (if used instead of custom implementation).

## Setup and Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/MrMalfunction/CareWalletBackend
    cd CareWalletBackend
    ```

2. **Set up AWS resources**:
    - Setup your AWS Credentials.
    - Change the ARN and domain for api gateway in the template.yaml file.

3. **Deploy the website**:
    - Upload the `index.html` and other necessary files to the S3 bucket.
    - Configure the S3 bucket for static website hosting.

4. **Deploy Backend**:
    - ```bash
      sam build --container
      sam deploy```
    - Make sure you have Docker installed and running.

5. **Configure environment variables**:
    - All lambda functions need to have these environment variables:
        - DB_ENC_KEY: Can be generated using fernet.generate_key()
        - FORMS_FILLED: forms_details
        - JWT_KEY: Some random string.
        - OTP_TABLE: user_otps
        - SESSION_TABLE: user_ssn
        - SES_SOURCE_EMAIL: whatever you prefer
        - USER_TABLE: user_details

## Usage

1. **Access the Website**:
    - Navigate to the URL of the hosted website on S3.

2. **Register/Login**:
    - Use the registration form to create a new account or log in with existing credentials.

3. **Fill Out Forms**:
    - After logging in, fill out and submit the intake forms available on the website.

4. **View Submitted Forms**:
    - Access previously submitted forms via the user dashboard after logging in.

## Demo hosted on: http://carewallet-amolbohora.s3-website-us-east-1.amazonaws.com/login.html

## Architecture

- **Frontend**: A static website hosted on AWS S3.
- **Backend**: DynamoDB for data storage, session management, and AWS Lambda for backend logic.
- **Session Management**: DynamoDB is used for managing user sessions, with TTL for automatic session expiration.

## Session Management

- **Login**: Users logs in and a new session is created.
- **Session Creation**: Upon successful login, a session is created and stored in DynamoDB with a session ID, user ID,
  and expiration time.
- **Session Validation**: Each time a user interacts with the website, their session is validated against DynamoDB.
- **Session Expiration**: Sessions automatically expire after a set period using DynamoDB's TTL feature.
    - Also python does a sanity check as an edge case to verify session has not expired.

## Data Storage

- **User Data**: Stored in DynamoDB under a user table.
- **Form Data**: Each submitted form is stored in DynamoDB.
- **Session Data**: Session information, including session ID and expiration time, is stored in DynamoDB.
- **Encryption**: All personal data is encrypted or anonymized. Data is decrypted once the sessions are a match and
  before sending to user.

## Security Considerations

- **HTTPS**: S3 Website doesn't support HTTPS, it's better to use other services to host the website, which have HTTPS
  support.<br>All of api data is transferred over https at all times.
- **Session Security**: Use secure session tokens and regularly validate them.
- **Data Encryption**: Encrypt sensitive data both in transit and at rest.
## License

This project is licensed under the MIT License.
