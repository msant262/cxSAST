import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { 
  AppBar, 
  Toolbar, 
  Typography, 
  Container, 
  Box, 
  ThemeProvider, 
  CssBaseline,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  IconButton,
  Avatar,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Assessment as AssessmentIcon,
  Settings as SettingsIcon,
  Code as CodeIcon,
  Menu as MenuIcon,
  Dashboard as DashboardIcon,
  PlayCircleOutline as StatusIcon,
} from '@mui/icons-material';
import ScanConfigPage from './pages/ScanConfig';
import ScanResultsPage from './pages/ScanResults';
import ScanStatusPage from './pages/ScanStatus';
import Dashboard from './pages/Dashboard';
import { theme } from './theme';
import NewScan from './pages/NewScan';
import ScanDetails from './pages/ScanDetails';

const drawerWidth = 240;

const Navigation = () => {
  const location = useLocation();

  const menuItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
    { text: 'New Scan', icon: <SecurityIcon />, path: '/new-scan' },
    { text: 'Scan Status', icon: <StatusIcon />, path: '/scan-status' },
    { text: 'Results', icon: <AssessmentIcon />, path: '/results' },
    { text: 'Rules', icon: <CodeIcon />, path: '/rules' },
    { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
  ];

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: drawerWidth,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: drawerWidth,
          boxSizing: 'border-box',
          backgroundColor: theme.palette.secondary.main,
          color: theme.palette.secondary.contrastText,
        },
      }}
    >
      <Toolbar sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <Avatar
          sx={{
            bgcolor: theme.palette.primary.main,
            width: 40,
            height: 40,
          }}
        >
          SV
        </Avatar>
        <Typography variant="h6" noWrap component="div">
          cxSAST
        </Typography>
      </Toolbar>
      <Divider sx={{ borderColor: 'rgba(255, 255, 255, 0.12)' }} />
      <List>
        {menuItems.map((item) => (
          <ListItem
            button
            key={item.text}
            component={Link}
            to={item.path}
            selected={location.pathname === item.path}
            sx={{
              '&.Mui-selected': {
                backgroundColor: theme.palette.primary.main,
                '&:hover': {
                  backgroundColor: theme.palette.primary.light,
                },
              },
              '&:hover': {
                backgroundColor: theme.palette.primary.main,
              },
            }}
          >
            <ListItemIcon sx={{ color: 'inherit' }}>
              {item.icon}
            </ListItemIcon>
            <ListItemText 
              primary={item.text}
              primaryTypographyProps={{
                fontWeight: location.pathname === item.path ? 600 : 400,
              }}
            />
          </ListItem>
        ))}
      </List>
    </Drawer>
  );
};

const App: React.FC = () => {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
          <Navigation />
          <Box
            component="main"
            sx={{
              flexGrow: 1,
              height: '100%',
              overflow: 'auto',
              backgroundColor: theme.palette.background.default,
            }}
          >
            <Toolbar />
            <Box sx={{ p: 4 }}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/new-scan" element={<NewScan />} />
                <Route path="/scan-status" element={<ScanStatusPage />} />
                <Route path="/scan-status/:scanId" element={<ScanStatusPage />} />
                <Route path="/scan-results/:scanId" element={<ScanResultsPage />} />
                <Route path="/results" element={<ScanResultsPage />} />
                <Route path="/rules" element={<div>Rules Page</div>} />
                <Route path="/settings" element={<div>Settings Page</div>} />
                <Route path="/scan/:scanId" element={<ScanDetails />} />
              </Routes>
            </Box>
          </Box>
        </Box>
      </Router>
    </ThemeProvider>
  );
};

export default App; 