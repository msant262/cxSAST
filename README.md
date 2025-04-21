# cxSAST - Static Application Security Testing Tool

cxSAST is a modern Static Application Security Testing (SAST) tool designed specifically for C and C++ code analysis. It helps identify security vulnerabilities in your codebase before they make it to production.

## Features

- Modern React-based user interface
- Support for both local files and Git repositories
- Configurable scanning rules
- Exclusion patterns for test directories
- OWASP Top 10 vulnerability detection
- Real-time scan progress monitoring
- Detailed vulnerability reports

## Getting Started

### Prerequisites

- Node.js (v16 or higher)
- npm (v7 or higher)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cxSAST.git
cd cxSAST
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

## Usage

1. Open your browser and navigate to `http://localhost:5173`
2. Choose your source type (Local Files or Git Repository)
3. Configure scan settings:
   - Source path
   - Exclude paths
   - Custom rules (optional)
4. Start the scan
5. View results in the Results page

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

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by VCG (VisualCodeGrepper) and Cppcheck
- OWASP Top 10 for vulnerability categories
- Material-UI for the beautiful interface components 