import React, { useState, useEffect, useMemo } from 'react';
import {
  Box,
  Typography,
  Paper,
  List,
  ListItem,
  ListItemText,
  Chip,
  Divider,
  FormControlLabel,
  Checkbox,
  TextField,
  Grid,
  CircularProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  IconButton,
  Tab,
  Tabs,
  Card,
  CardContent,
  Stack,
  useTheme,
  Link,
  InputAdornment,
} from '@mui/material';
import {
  Close as CloseIcon,
  DataObject as DataObjectIcon,
  Code as CodeIcon,
  Info as InfoIcon,
  BugReport as BugReportIcon,
  Security as SecurityIcon,
  Shield as ShieldIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  OpenInNew as OpenInNewIcon,
  Search as SearchIcon,
  Clear as ClearIcon,
} from '@mui/icons-material';
import { useParams } from 'react-router-dom';
import { 
  getScanDetails, 
  getScanResults, 
  getSourceCode,
  markVulnerabilityAsIgnored,
  markVulnerabilityAsFalsePositive,
  type ScanDetails,
  type ScanResult,
  type VulnerabilityDetails,
  API_BASE_URL
} from '../services/api';
import axios from 'axios';

const severityIcons = {
  CRITICAL: <ErrorIcon color="error" />,
  HIGH: <ErrorIcon color="error" />,
  MEDIUM: <WarningIcon color="warning" />,
  LOW: <InfoIcon color="info" />,
  INFORMATIONAL: <InfoIcon color="info" />,
} as const;

const severityColors = {
  CRITICAL: 'error',
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'info',
  INFORMATIONAL: 'info',
} as const;

const severityChipColors = {
  CRITICAL: {
    background: 'rgba(211, 47, 47, 0.1)',
    color: '#d32f2f',
    border: '1px solid rgba(211, 47, 47, 0.3)',
  },
  HIGH: {
    background: 'rgba(211, 47, 47, 0.1)',
    color: '#d32f2f',
    border: '1px solid rgba(211, 47, 47, 0.3)',
  },
  MEDIUM: {
    background: 'rgba(237, 108, 2, 0.1)',
    color: '#ed6c02',
    border: '1px solid rgba(237, 108, 2, 0.3)',
  },
  LOW: {
    background: 'rgba(2, 136, 209, 0.1)',
    color: '#0288d1',
    border: '1px solid rgba(2, 136, 209, 0.3)',
  },
  INFORMATIONAL: {
    background: 'rgba(158, 158, 158, 0.1)',
    color: '#757575',
    border: '1px solid rgba(158, 158, 158, 0.3)',
  },
} as const;

const formatDuration = (milliseconds: number): string => {
  const seconds = Math.floor(milliseconds / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  } else {
    return `${seconds}s`;
  }
};

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`vulnerability-tabpanel-${index}`}
      aria-labelledby={`vulnerability-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

interface Vulnerability {
  id: string;
  file: string;
  line: number;
  rule: string;
  message: string;
  severity: string;
  isIgnored: boolean;
  isFalsePositive: boolean;
  sourceCode?: {
    snippet: string;
    startLine: number;
    endLine: number;
    highlightedLines: number[];
    fullContent: string;
    totalLines: number;
  };
  cwe?: {
    id: string;
    name: string;
    description: string;
    mitreUrl: string;
  };
  cve?: {
    id: string;
    description: string;
    cvssScore?: number;
    nvdUrl: string;
  };
  remediation?: {
    description: string;
    steps: string[];
    references: string[];
  };
}

interface ScanResults {
  vulnerabilities: Vulnerability[];
  totalIssues: number;
}

const ScanDetailsPage: React.FC = () => {
  const { scanId } = useParams();
  const [scanDetails, setScanDetails] = useState<ScanDetails | null>(null);
  const [results, setResults] = useState<ScanResults>({
    vulnerabilities: [],
    totalIssues: 0
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);
  const [tabValue, setTabValue] = useState(0);
  const theme = useTheme();

  useEffect(() => {
    console.log('Results state changed:', results);
  }, [results]);

  useEffect(() => {
    fetchData();
    let intervalId: any;

    // Only start polling if scan is not completed and dialog is not open
    if ((!scanDetails || scanDetails.status.toUpperCase() !== 'COMPLETED') && !detailsDialogOpen) {
      intervalId = setInterval(fetchData, 5000);
    }

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [scanId, detailsDialogOpen]);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);

      // First fetch scan details
      const details = await getScanDetails(scanId!);
      setScanDetails(details);
      console.log('Scan details:', details);

      // If scan is completed, fetch results
      if (details.status.toUpperCase() === 'COMPLETED') {
        console.log('Fetching vulnerabilities...');
        const vulnerabilitiesData = await getScanResults(scanId!);
        console.log('Raw vulnerabilities data:', vulnerabilitiesData);
        
        const vulnerabilities: Vulnerability[] = vulnerabilitiesData.map(result => ({
          id: result.id,
          file: result.file,
          line: result.line,
          rule: result.rule,
          message: result.message,
          severity: result.severity,
          isIgnored: result.isIgnored ?? false,
          isFalsePositive: result.isFalsePositive ?? false,
          sourceCode: result.details?.sourceCode,
          cwe: result.details?.cwe,
          cve: result.details?.cve,
          remediation: result.details?.remediation
        }));
        
        console.log('Processed vulnerabilities:', vulnerabilities);
        
        setResults({
          vulnerabilities,
          totalIssues: vulnerabilities.length
        });
        console.log('Updated results state:', {
          vulnerabilities,
          totalIssues: vulnerabilities.length
        });
      }
    } catch (err) {
      console.error('Error fetching data:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch scan data');
    } finally {
      setLoading(false);
    }
  };

  const handleSeverityFilterChange = (severity: string) => {
    setSelectedSeverities(prev => {
      if (prev.includes(severity)) {
        return prev.filter(s => s !== severity);
      }
      return [...prev, severity];
    });
  };

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchQuery(event.target.value);
  };

  const filteredVulnerabilities = useMemo(() => {
    console.log('Filtering vulnerabilities:', {
      results,
      selectedSeverities,
      searchQuery
    });

    const filtered = results.vulnerabilities.filter(vulnerability => {
      // Filter by severity
      if (selectedSeverities.length > 0 && !selectedSeverities.includes(vulnerability.severity)) {
        return false;
      }
      
      // Filter by search query
      if (searchQuery) {
        const searchLower = searchQuery.toLowerCase();
        return (
          vulnerability.file.toLowerCase().includes(searchLower) ||
          vulnerability.message.toLowerCase().includes(searchLower) ||
          vulnerability.rule.toLowerCase().includes(searchLower)
        );
      }
      
      return true;
    });

    console.log('Filtered vulnerabilities:', filtered);
    return filtered;
  }, [results.vulnerabilities, selectedSeverities, searchQuery]);

  const formatFilePath = (path: string): string => {
    const extractedIndex = path.indexOf('extracted/');
    if (extractedIndex === -1) return path;
    return path.substring(extractedIndex + 'extracted/'.length);
  };

  const handleVulnerabilityClick = async (vulnerability: Vulnerability) => {
    try {
      // If we already have source code details, no need to fetch again
      if (!vulnerability.sourceCode) {
        const sourceCode = await getSourceCode(vulnerability.file, vulnerability.line);
        vulnerability = {
          ...vulnerability,
          sourceCode,
        };
      }
      setSelectedVulnerability(vulnerability);
      setDetailsDialogOpen(true);
    } catch (err) {
      console.error('Error fetching vulnerability details:', err);
      setError('Failed to load vulnerability details');
    }
  };

  const handleCloseDialog = () => {
    setDetailsDialogOpen(false);
    setSelectedVulnerability(null);
    setTabValue(0);
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const handleMarkIgnored = async (vulnerability: Vulnerability) => {
    try {
      const response = await fetch(`/api/vulnerability/${vulnerability.id}/ignore`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!response.ok) throw new Error('Failed to mark vulnerability as ignored');

      setResults(prevResults => ({
        ...prevResults,
        vulnerabilities: prevResults.vulnerabilities.map(v => 
          v.id === vulnerability.id ? { ...v, isIgnored: !v.isIgnored } : v
        )
      }));
      setDetailsDialogOpen(false);
    } catch (error) {
      console.error('Error marking vulnerability as ignored:', error);
    }
  };

  const handleMarkFalsePositive = async (vulnerability: Vulnerability) => {
    try {
      const response = await fetch(`/api/vulnerability/${vulnerability.id}/false-positive`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!response.ok) throw new Error('Failed to mark vulnerability as false positive');

      setResults(prevResults => ({
        ...prevResults,
        vulnerabilities: prevResults.vulnerabilities.map(v => 
          v.id === vulnerability.id ? { ...v, isFalsePositive: !v.isFalsePositive } : v
        )
      }));
      setDetailsDialogOpen(false);
    } catch (error) {
      console.error('Error marking vulnerability as false positive:', error);
    }
  };

  const handleMarkAsFalsePositive = async (vulnerability: Vulnerability) => {
    try {
      await axios.post(`${API_BASE_URL}/scan/${scanId}/vulnerabilities/${vulnerability.id}/false-positive`);
      await fetchData(); // Refresh the data
    } catch (err) {
      console.error('Error marking vulnerability as false positive:', err);
      setError('Failed to mark vulnerability as false positive');
    }
  };

  const handleMarkAsTruePositive = async (vulnerability: Vulnerability) => {
    try {
      await axios.post(`${API_BASE_URL}/scan/${scanId}/vulnerabilities/${vulnerability.id}/true-positive`);
      await fetchData(); // Refresh the data
    } catch (err) {
      console.error('Error marking vulnerability as true positive:', err);
      setError('Failed to mark vulnerability as true positive');
    }
  };

  const severityCounts = useMemo(() => {
    console.log('Calculating severity counts from:', results.vulnerabilities);
    
    const counts = {
      CRITICAL: results.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
      HIGH: results.vulnerabilities.filter(v => v.severity === 'HIGH').length,
      MEDIUM: results.vulnerabilities.filter(v => v.severity === 'MEDIUM').length,
      LOW: results.vulnerabilities.filter(v => v.severity === 'LOW').length,
      INFORMATIONAL: results.vulnerabilities.filter(v => v.severity === 'INFORMATIONAL').length,
    };
    
    console.log('Calculated severity counts:', counts);
    return counts;
  }, [results.vulnerabilities]);

  if (loading) {
    return (
      <Box 
        sx={{ 
          display: 'flex', 
          justifyContent: 'center', 
          alignItems: 'center', 
          height: '100vh',
          backgroundColor: theme.palette.background.default,
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3, backgroundColor: theme.palette.background.default }}>
        <Alert 
          severity="error" 
          sx={{ 
            mb: 3,
            '& .MuiAlert-icon': {
              fontSize: '2rem',
            },
          }}
        >
          {error}
        </Alert>
      </Box>
    );
  }

  if (!scanDetails) {
    return (
      <Box sx={{ p: 3, backgroundColor: theme.palette.background.default }}>
        <Alert 
          severity="info"
          sx={{ 
            '& .MuiAlert-icon': {
              fontSize: '2rem',
            },
          }}
        >
          No scan details available
        </Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      {/* Modern Header */}
      <Box sx={{ mb: 4, display: 'flex', alignItems: 'center', gap: 2 }}>
        <SecurityIcon sx={{ fontSize: 40, color: 'primary.main' }} />
        <Box>
          <Typography variant="h4" component="h1" gutterBottom>
            Security Scan Results
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            {scanDetails?.projectName}
          </Typography>
        </Box>
      </Box>

      {/* Status Card */}
      <Card sx={{ mb: 3, bgcolor: 'background.paper' }}>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <Chip
              label={scanDetails?.status}
              color={scanDetails?.status.toUpperCase() === 'COMPLETED' ? 'success' : 'warning'}
              icon={scanDetails?.status.toUpperCase() === 'COMPLETED' ? <CheckCircleIcon /> : <CircularProgress size={20} />}
            />
            <Typography variant="body2" color="text.secondary">
              Started: {new Date(scanDetails?.startTime || '').toLocaleString()}
            </Typography>
            {scanDetails?.endTime && (
              <Typography variant="body2" color="text.secondary">
                Completed: {new Date(scanDetails.endTime).toLocaleString()}
              </Typography>
            )}
          </Box>
        </CardContent>
      </Card>

      {/* Metrics Grid */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <DataObjectIcon color="primary" />
                <Typography variant="subtitle2" color="text.secondary">
                  Total Files
                </Typography>
              </Box>
              <Typography variant="h4">
                {scanDetails?.totalFiles}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <BugReportIcon color="error" />
                <Typography variant="subtitle2" color="text.secondary">
                  Total Issues
                </Typography>
              </Box>
              <Typography variant="h4">
                {scanDetails?.totalIssues}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <CodeIcon color="info" />
                <Typography variant="subtitle2" color="text.secondary">
                  Lines of Code
                </Typography>
              </Box>
              <Typography variant="h4">
                {scanDetails?.totalLoc?.toLocaleString()}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card sx={{ height: '100%' }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <ShieldIcon color="success" />
                <Typography variant="subtitle2" color="text.secondary">
                  Security Score
                </Typography>
              </Box>
              <Typography variant="h4">
                {scanDetails?.totalIssues ? 
                  Math.max(0, 100 - (scanDetails.totalIssues * 10)) : 
                  100}%
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        {/* Vulnerability Counts by Severity */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="subtitle1" gutterBottom>
                Vulnerabilities by Severity
              </Typography>
              <Grid container spacing={2}>
                {Object.entries(severityCounts).map(([severity, count]) => (
                  <Grid item xs={12} sm={6} md={2.4} key={severity}>
                    <Box
                      onClick={() => handleSeverityFilterChange(severity)}
                      sx={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        p: 2,
                        borderRadius: 1,
                        bgcolor: selectedSeverities.includes(severity)
                          ? severityChipColors[severity as keyof typeof severityChipColors].background
                          : 'transparent',
                        border: `1px solid ${severityChipColors[severity as keyof typeof severityChipColors].border}`,
                        cursor: 'pointer',
                        transition: 'all 0.2s',
                        '&:hover': {
                          transform: 'translateY(-2px)',
                          boxShadow: '0 4px 8px rgba(0,0,0,0.1)',
                        },
                        position: 'relative',
                        overflow: 'hidden',
                        '&::after': selectedSeverities.includes(severity) ? {
                          content: '""',
                          position: 'absolute',
                          top: 0,
                          right: 0,
                          width: '20px',
                          height: '20px',
                          background: severityChipColors[severity as keyof typeof severityChipColors].color,
                          clipPath: 'polygon(100% 0, 100% 100%, 0 0)',
                        } : {},
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                        {severityIcons[severity as keyof typeof severityIcons]}
                        <Typography
                          variant="subtitle2"
                          sx={{ 
                            color: severityChipColors[severity as keyof typeof severityChipColors].color,
                            fontWeight: selectedSeverities.includes(severity) ? 600 : 400,
                          }}
                        >
                          {severity}
                        </Typography>
                      </Box>
                      <Typography
                        variant="h4"
                        sx={{ 
                          color: severityChipColors[severity as keyof typeof severityChipColors].color,
                          fontWeight: selectedSeverities.includes(severity) ? 700 : 400,
                        }}
                      >
                        {count}
                      </Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Search Bar */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <TextField
            fullWidth
            variant="outlined"
            placeholder="Search vulnerabilities by file, message, or rule..."
            value={searchQuery}
            onChange={handleSearchChange}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon />
                </InputAdornment>
              ),
              endAdornment: searchQuery && (
                <InputAdornment position="end">
                  <IconButton
                    size="small"
                    onClick={() => setSearchQuery('')}
                  >
                    <ClearIcon />
                  </IconButton>
                </InputAdornment>
              ),
            }}
            sx={{
              '& .MuiOutlinedInput-root': {
                borderRadius: 2,
                backgroundColor: 'background.paper',
              },
            }}
          />
        </CardContent>
      </Card>

      {/* Vulnerabilities List */}
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">
              Vulnerabilities ({filteredVulnerabilities.length})
            </Typography>
            {searchQuery && (
              <Typography variant="body2" color="text.secondary">
                Showing results for: "{searchQuery}"
              </Typography>
            )}
          </Box>
          {filteredVulnerabilities.length === 0 ? (
            <Alert severity="info" sx={{ mt: 2 }}>
              {searchQuery 
                ? 'No vulnerabilities found matching your search criteria.'
                : 'No vulnerabilities found matching the selected filters.'}
            </Alert>
          ) : (
            <List>
              {filteredVulnerabilities.map((vulnerability, index) => (
                <React.Fragment key={vulnerability.id}>
                  {index > 0 && <Divider />}
                  <ListItem
                    button
                    onClick={() => handleVulnerabilityClick(vulnerability)}
                    sx={{
                      '&:hover': {
                        backgroundColor: 'action.hover',
                      },
                    }}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                          {severityIcons[vulnerability.severity as keyof typeof severityIcons]}
                          <Typography variant="subtitle1">
                            {vulnerability.rule}
                          </Typography>
                          <Chip
                            label={vulnerability.severity}
                            size="small"
                            sx={{
                              backgroundColor: `${severityColors[vulnerability.severity as keyof typeof severityColors]}.main`,
                              color: 'white',
                            }}
                          />
                          {vulnerability.isIgnored && (
                            <Chip
                              label="Ignored"
                              size="small"
                              color="warning"
                            />
                          )}
                          {vulnerability.isFalsePositive && (
                            <Chip
                              label="False Positive"
                              size="small"
                              color="info"
                            />
                          )}
                        </Box>
                      }
                      secondary={
                        <Box>
                          <Typography variant="body2" color="text.secondary">
                            {vulnerability.message}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {formatFilePath(vulnerability.file)}:{vulnerability.line}
                          </Typography>
                          {vulnerability.cwe && (
                            <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                              CWE-{vulnerability.cwe.id}: {vulnerability.cwe.name}
                            </Typography>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                </React.Fragment>
              ))}
            </List>
          )}
        </CardContent>
      </Card>

      {/* Vulnerability Details Dialog */}
      <Dialog
        open={detailsDialogOpen}
        onClose={handleCloseDialog}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: {
            borderRadius: 2,
            boxShadow: '0 8px 32px rgba(0,0,0,0.1)',
          }
        }}
      >
        {selectedVulnerability && (
          <>
            <DialogTitle sx={{ 
              borderBottom: '1px solid',
              borderColor: 'divider',
              pb: 2,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <Box>
                <Typography variant="h5" component="div" gutterBottom>
                  {selectedVulnerability.rule}
                </Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Chip
                    label={selectedVulnerability.severity}
                    color={severityColors[selectedVulnerability.severity as keyof typeof severityColors]}
                    size="small"
                  />
                  {selectedVulnerability.cwe && (
                    <Chip
                      label={`CWE-${selectedVulnerability.cwe.id}`}
                      variant="outlined"
                      size="small"
                      icon={<OpenInNewIcon fontSize="small" />}
                      onClick={() => window.open(selectedVulnerability.cwe?.mitreUrl, '_blank')}
                    />
                  )}
                </Box>
              </Box>
              <Box sx={{ display: 'flex', gap: 1 }}>
                {selectedVulnerability.isFalsePositive ? (
                  <Button
                    variant="outlined"
                    color="success"
                    onClick={() => handleMarkAsTruePositive(selectedVulnerability)}
                  >
                    Mark as True Positive
                  </Button>
                ) : (
                  <Button
                    variant="outlined"
                    color="error"
                    onClick={() => handleMarkAsFalsePositive(selectedVulnerability)}
                  >
                    Mark as False Positive
                  </Button>
                )}
                <IconButton onClick={handleCloseDialog} size="small">
                  <CloseIcon />
                </IconButton>
              </Box>
            </DialogTitle>
            <DialogContent sx={{ p: 3 }}>
              <Box sx={{ mb: 3 }}>
                <Tabs 
                  value={tabValue} 
                  onChange={handleTabChange}
                  sx={{
                    borderBottom: 1,
                    borderColor: 'divider',
                    '& .MuiTab-root': {
                      textTransform: 'none',
                      fontWeight: 500,
                    }
                  }}
                >
                  <Tab label="Overview" icon={<InfoIcon />} iconPosition="start" />
                  <Tab label="Source Code" icon={<CodeIcon />} iconPosition="start" />
                  <Tab label="CWE Details" icon={<SecurityIcon />} iconPosition="start" />
                  <Tab label="Remediation" icon={<ShieldIcon />} iconPosition="start" />
                </Tabs>
              </Box>

              {/* Overview Tab */}
              <TabPanel value={tabValue} index={0}>
                <Grid container spacing={3}>
                  <Grid item xs={12}>
                    <Card variant="outlined">
                      <CardContent>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                          <Box sx={{ 
                            p: 1.5, 
                            borderRadius: 1,
                            bgcolor: `${severityColors[selectedVulnerability.severity as keyof typeof severityColors]}.light`,
                            color: `${severityColors[selectedVulnerability.severity as keyof typeof severityColors]}.dark`,
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}>
                            {severityIcons[selectedVulnerability.severity as keyof typeof severityIcons]}
                          </Box>
                          <Box>
                            <Typography variant="h6" gutterBottom>
                              {selectedVulnerability.rule}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              {selectedVulnerability.message}
                            </Typography>
                          </Box>
                        </Box>
                        <Divider sx={{ my: 2 }} />
                        <Grid container spacing={2}>
                          <Grid item xs={12} sm={6}>
                            <Box sx={{ mb: 2 }}>
                              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                Location
                              </Typography>
                              <Box sx={{ 
                                display: 'flex', 
                                alignItems: 'center', 
                                gap: 1,
                                p: 1.5,
                                borderRadius: 1,
                                bgcolor: 'background.default',
                                border: '1px solid',
                                borderColor: 'divider',
                              }}>
                                <CodeIcon color="action" />
                                <Box>
                                  <Typography variant="body2" sx={{ fontWeight: 500 }}>
                                    {formatFilePath(selectedVulnerability.file)}
                                  </Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    Line {selectedVulnerability.line}
                                  </Typography>
                                </Box>
                              </Box>
                            </Box>
                            <Box>
                              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                Status
                              </Typography>
                              <Box sx={{ 
                                display: 'flex', 
                                gap: 1,
                                p: 1.5,
                                borderRadius: 1,
                                bgcolor: 'background.default',
                                border: '1px solid',
                                borderColor: 'divider',
                              }}>
                                <Chip
                                  label={selectedVulnerability.severity}
                                  color={severityColors[selectedVulnerability.severity as keyof typeof severityColors]}
                                  size="small"
                                  sx={{ fontWeight: 500 }}
                                />
                                {selectedVulnerability.isIgnored && (
                                  <Chip
                                    label="Ignored"
                                    color="warning"
                                    size="small"
                                    sx={{ fontWeight: 500 }}
                                  />
                                )}
                                {selectedVulnerability.isFalsePositive && (
                                  <Chip
                                    label="False Positive"
                                    color="info"
                                    size="small"
                                    sx={{ fontWeight: 500 }}
                                  />
                                )}
                              </Box>
                            </Box>
                          </Grid>
                          <Grid item xs={12} sm={6}>
                            {selectedVulnerability.cwe && (
                              <Box sx={{ mb: 2 }}>
                                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                  CWE Information
                                </Typography>
                                <Box sx={{ 
                                  display: 'flex', 
                                  alignItems: 'flex-start', 
                                  gap: 1.5,
                                  p: 1.5,
                                  borderRadius: 1,
                                  bgcolor: 'background.default',
                                  border: '1px solid',
                                  borderColor: 'divider',
                                }}>
                                  <SecurityIcon color="action" sx={{ mt: 0.5 }} />
                                  <Box>
                                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                                      CWE-{selectedVulnerability.cwe.id}: {selectedVulnerability.cwe.name}
                                    </Typography>
                                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                                      {selectedVulnerability.cwe.description}
                                    </Typography>
                                    <Button
                                      size="small"
                                      startIcon={<OpenInNewIcon />}
                                      onClick={() => window.open(selectedVulnerability.cwe?.mitreUrl, '_blank')}
                                      sx={{ mt: 1 }}
                                    >
                                      View on MITRE
                                    </Button>
                                  </Box>
                                </Box>
                              </Box>
                            )}
                            {selectedVulnerability.cve && (
                              <Box>
                                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                  CVE Information
                                </Typography>
                                <Box sx={{ 
                                  display: 'flex', 
                                  alignItems: 'flex-start', 
                                  gap: 1.5,
                                  p: 1.5,
                                  borderRadius: 1,
                                  bgcolor: 'background.default',
                                  border: '1px solid',
                                  borderColor: 'divider',
                                }}>
                                  <BugReportIcon color="action" sx={{ mt: 0.5 }} />
                                  <Box>
                                    <Typography variant="body2" sx={{ fontWeight: 500 }}>
                                      {selectedVulnerability.cve.id}
                                    </Typography>
                                    <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                                      {selectedVulnerability.cve.description}
                                    </Typography>
                                    {selectedVulnerability.cve.cvssScore && (
                                      <Box sx={{ 
                                        display: 'flex', 
                                        alignItems: 'center', 
                                        gap: 1,
                                        mt: 1,
                                      }}>
                                        <Typography variant="caption" color="text.secondary">
                                          CVSS Score:
                                        </Typography>
                                        <Chip
                                          label={selectedVulnerability.cve.cvssScore}
                                          size="small"
                                          color={selectedVulnerability.cve.cvssScore >= 7 ? 'error' : 
                                                 selectedVulnerability.cve.cvssScore >= 4 ? 'warning' : 'info'}
                                          sx={{ fontWeight: 500 }}
                                        />
                                      </Box>
                                    )}
                                    <Button
                                      size="small"
                                      startIcon={<OpenInNewIcon />}
                                      onClick={() => window.open(selectedVulnerability.cve?.nvdUrl, '_blank')}
                                      sx={{ mt: 1 }}
                                    >
                                      View on NVD
                                    </Button>
                                  </Box>
                                </Box>
                              </Box>
                            )}
                          </Grid>
                        </Grid>
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </TabPanel>

              {/* Source Code Tab */}
              <TabPanel value={tabValue} index={1}>
                {selectedVulnerability.sourceCode ? (
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ 
                        bgcolor: 'background.paper', 
                        p: 1, 
                        borderRadius: 1,
                        fontFamily: 'monospace',
                        whiteSpace: 'pre-wrap',
                        overflowX: 'auto',
                        fontSize: '0.75rem',
                        lineHeight: 1.2,
                      }}>
                        {selectedVulnerability.sourceCode?.snippet.split('\n').map((line, index) => (
                          <Box
                            key={index}
                            sx={{
                              display: 'flex',
                              alignItems: 'flex-start',
                              gap: 2,
                              bgcolor: selectedVulnerability.sourceCode?.highlightedLines?.includes(index + (selectedVulnerability.sourceCode?.startLine || 0)) 
                                ? 'rgba(211, 47, 47, 0.1)' 
                                : 'transparent',
                              p: 0.5,
                              borderRadius: 1,
                              minHeight: '1.5em',
                            }}
                          >
                            <Typography
                              variant="caption"
                              sx={{
                                color: 'text.secondary',
                                minWidth: '2em',
                                textAlign: 'right',
                                userSelect: 'none',
                                fontSize: '0.75rem',
                              }}
                            >
                              {index + (selectedVulnerability.sourceCode?.startLine || 0)}
                            </Typography>
                            <Typography
                              sx={{
                                fontFamily: 'monospace',
                                whiteSpace: 'pre-wrap',
                                flex: 1,
                                fontSize: '0.75rem',
                              }}
                            >
                              {line}
                            </Typography>
                          </Box>
                        ))}
                      </Box>
                    </CardContent>
                  </Card>
                ) : (
                  <Alert severity="info">
                    Source code not available
                  </Alert>
                )}
              </TabPanel>

              {/* CWE Details Tab */}
              <TabPanel value={tabValue} index={2}>
                {selectedVulnerability.cwe ? (
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
                        <Box sx={{ 
                          p: 1.5, 
                          borderRadius: 1,
                          bgcolor: 'primary.light',
                          color: 'primary.dark',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}>
                          <SecurityIcon />
                        </Box>
                        <Box>
                          <Typography variant="h5" gutterBottom>
                            CWE-{selectedVulnerability.cwe.id}: {selectedVulnerability.cwe.name}
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            Common Weakness Enumeration
                          </Typography>
                        </Box>
                      </Box>

                      <Grid container spacing={3}>
                        <Grid item xs={12} md={8}>
                          <Card variant="outlined">
                            <CardContent>
                              <Typography variant="subtitle1" gutterBottom>
                                Description
                              </Typography>
                              <Typography variant="body2" paragraph>
                                {selectedVulnerability.cwe.description}
                              </Typography>
                              <Button
                                variant="outlined"
                                startIcon={<OpenInNewIcon />}
                                onClick={() => window.open(selectedVulnerability.cwe?.mitreUrl, '_blank')}
                                sx={{ mt: 2 }}
                              >
                                View on MITRE
                              </Button>
                            </CardContent>
                          </Card>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Card variant="outlined">
                            <CardContent>
                              <Typography variant="subtitle1" gutterBottom>
                                Related Information
                              </Typography>
                              <List dense>
                                <ListItem>
                                  <ListItemText
                                    primary="CWE ID"
                                    secondary={selectedVulnerability.cwe.id}
                                  />
                                </ListItem>
                                <Divider />
                                <ListItem>
                                  <ListItemText
                                    primary="Name"
                                    secondary={selectedVulnerability.cwe.name}
                                  />
                                </ListItem>
                                <Divider />
                                <ListItem>
                                  <ListItemText
                                    primary="Category"
                                    secondary="Software Development"
                                  />
                                </ListItem>
                              </List>
                            </CardContent>
                          </Card>
                        </Grid>
                      </Grid>
                    </CardContent>
                  </Card>
                ) : (
                  <Alert severity="info">
                    No CWE information available
                  </Alert>
                )}
              </TabPanel>

              {/* Remediation Tab */}
              <TabPanel value={tabValue} index={3}>
                {selectedVulnerability.remediation ? (
                  <Card variant="outlined">
                    <CardContent>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
                        <Box sx={{ 
                          p: 1.5, 
                          borderRadius: 1,
                          bgcolor: 'success.light',
                          color: 'success.dark',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                        }}>
                          <ShieldIcon />
                        </Box>
                        <Box>
                          <Typography variant="h5" gutterBottom>
                            Remediation Guide
                          </Typography>
                          <Typography variant="body2" color="text.secondary">
                            Steps to fix this vulnerability
                          </Typography>
                        </Box>
                      </Box>

                      <Grid container spacing={3}>
                        <Grid item xs={12} md={8}>
                          <Card variant="outlined">
                            <CardContent>
                              <Typography variant="subtitle1" gutterBottom>
                                Description
                              </Typography>
                              <Typography variant="body2" paragraph>
                                {selectedVulnerability.remediation.description}
                              </Typography>

                              <Typography variant="subtitle1" gutterBottom sx={{ mt: 3 }}>
                                Remediation Steps
                              </Typography>
                              <List>
                                {selectedVulnerability.remediation.steps.map((step, index) => (
                                  <ListItem key={index} sx={{ py: 1 }}>
                                    <ListItemText
                                      primary={
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                          <Chip
                                            label={`Step ${index + 1}`}
                                            size="small"
                                            color="primary"
                                            variant="outlined"
                                          />
                                          <Typography variant="body2">
                                            {step}
                                          </Typography>
                                        </Box>
                                      }
                                    />
                                  </ListItem>
                                ))}
                              </List>
                            </CardContent>
                          </Card>
                        </Grid>
                        <Grid item xs={12} md={4}>
                          <Card variant="outlined">
                            <CardContent>
                              <Typography variant="subtitle1" gutterBottom>
                                References
                              </Typography>
                              <List dense>
                                {selectedVulnerability.remediation.references.map((ref, index) => (
                                  <ListItem key={index} sx={{ py: 1 }}>
                                    <ListItemText
                                      primary={
                                        <Link
                                          href={ref}
                                          target="_blank"
                                          rel="noopener noreferrer"
                                          sx={{ 
                                            display: 'flex', 
                                            alignItems: 'center', 
                                            gap: 0.5,
                                            color: 'primary.main',
                                            textDecoration: 'none',
                                            '&:hover': {
                                              textDecoration: 'underline',
                                            },
                                          }}
                                        >
                                          Reference {index + 1}
                                          <OpenInNewIcon fontSize="small" />
                                        </Link>
                                      }
                                    />
                                  </ListItem>
                                ))}
                              </List>
                            </CardContent>
                          </Card>
                        </Grid>
                      </Grid>
                    </CardContent>
                  </Card>
                ) : (
                  <Alert severity="info">
                    No remediation information available
                  </Alert>
                )}
              </TabPanel>
            </DialogContent>
            <DialogActions sx={{ p: 3, borderTop: '1px solid', borderColor: 'divider' }}>
              <Button onClick={handleCloseDialog}>Close</Button>
              <Button
                variant="contained"
                color={selectedVulnerability.isIgnored ? "secondary" : "warning"}
                onClick={() => handleMarkIgnored(selectedVulnerability)}
              >
                {selectedVulnerability.isIgnored ? "Unignore" : "Ignore"}
              </Button>
              <Button
                variant="contained"
                color={selectedVulnerability.isFalsePositive ? "secondary" : "info"}
                onClick={() => handleMarkFalsePositive(selectedVulnerability)}
              >
                {selectedVulnerability.isFalsePositive ? "Mark as Valid" : "Mark as False Positive"}
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Box>
  );
};

export default ScanDetailsPage; 