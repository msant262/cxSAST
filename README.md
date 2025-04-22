# cxSAST - Code Security Analysis Tool

A static application security testing (SAST) tool that helps identify potential security vulnerabilities in your code.

## Features

- Code vulnerability scanning
- Multiple programming language support
- User authentication
- Project management
- Detailed vulnerability reports
- Remediation suggestions

## Prerequisites

- Python 3.8+
- Node.js 16+
- npm or yarn

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cxSAST.git
cd cxSAST
```

2. Set up the backend:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Set up the frontend:
```bash
cd frontend
npm install
```

## Running the Application

1. Start the backend server:
```bash
cd backend
source venv/bin/activate  # On Windows: venv\Scripts\activate
python -m uvicorn app.main:app --reload
```

2. Start the frontend development server:
```bash
cd frontend
npm run dev
```

3. Access the application:
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Documentation: http://localhost:8000/docs

## Usage

1. Register a new user account or login with existing credentials
2. Create a new scan by providing a project name and uploading source code files
3. View scan results and detailed vulnerability reports
4. Review remediation suggestions for identified vulnerabilities

## API Documentation

The API documentation is available at http://localhost:8000/docs when the backend server is running.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Project Structure

```
src/
├── components/     # Reusable UI components
├── pages/         # Page components
├── services/      # API and business logic
├── types/         # TypeScript type definitions
├── utils/         # Utility functions
└── config/        # Configuration files
```

## Acknowledgments

- Inspired by VCG (VisualCodeGrepper) and Cppcheck
- OWASP Top 10 for vulnerability categories
- Material-UI for the beautiful interface components 