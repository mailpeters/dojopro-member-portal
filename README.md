# DojoPro Member Portal

A modern, responsive member portal for martial arts clubs built with Node.js and Express.

## Features

### 🔐 **Authentication & Security**
- Automatic user account creation for new members
- Secure password setup flow
- Club-specific member isolation
- Session-based authentication

### 🎨 **Dynamic Branding**
- Club-specific logos and colors
- Subdomain-based club separation
- Responsive design matching admin portal
- Mobile-first approach

### 📊 **Member Dashboard**
- Training statistics and progress tracking
- Current check-in status
- Recent training session history
- Personal profile information

### ⚙️ **Technical Features**
- RESTful API design
- MySQL/MariaDB database integration
- EJS templating engine
- Flash messaging system
- Comprehensive error handling

## Installation

### Prerequisites
- Node.js 16+ 
- MySQL/MariaDB
- Admin portal already set up

### Setup
```bash
# Clone repository
git clone https://github.com/mailpeters/dojopro-member-portal.git
cd dojopro-member-portal

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your database credentials

# Start development server
npm run dev
