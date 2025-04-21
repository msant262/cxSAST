import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { AppBar, Toolbar, Typography, Container, Box } from '@mui/material';
import ScanConfigPage from './pages/ScanConfig';
import ScanResultsPage from './pages/ScanResults';

const App: React.FC = () => {
  return (
    <Router>
      <Box sx={{ flexGrow: 1 }}>
        <AppBar position="static">
          <Toolbar>
            <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
              cxSAST
            </Typography>
            <Box sx={{ display: 'flex', gap: 2 }}>
              <Link to="/" style={{ color: 'white', textDecoration: 'none' }}>
                Scan
              </Link>
              <Link to="/results" style={{ color: 'white', textDecoration: 'none' }}>
                Results
              </Link>
            </Box>
          </Toolbar>
        </AppBar>
        <Container maxWidth="lg" sx={{ mt: 4 }}>
          <Routes>
            <Route path="/" element={<ScanConfigPage />} />
            <Route path="/results" element={<ScanResultsPage results={[]} />} />
          </Routes>
        </Container>
      </Box>
    </Router>
  );
};

export default App; 