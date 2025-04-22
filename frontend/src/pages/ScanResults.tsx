import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  LinearProgress,
  Alert,
  CircularProgress,
  List,
  ListItem,
  ListItemText,
  Chip,
  Divider,
  Collapse,
  IconButton,
  ListItemButton,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Card,
  CardContent,
  Grid,
} from '@mui/material';
import { ExpandLess, ExpandMore, Cancel, Refresh } from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';
import { ScanStatus, getScanStatus, getScanResults, api } from '../services/api';

const statusColors = {
  PENDING: 'warning',
  RUNNING: 'info',
  COMPLETED: 'success',
  FAILED: 'error',
  CANCELLED: 'error',
} as const;

const severityColors = {
  HIGH: 'error',
  MEDIUM: 'warning',
  LOW: 'info',
} as const;

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleString();
};

const formatDuration = (startTime: string, endTime: string | null) => {
  const start = new Date(startTime);
  const end = endTime ? new Date(endTime) : new Date();
  const diff = end.getTime() - start.getTime();

  const hours = Math.floor(diff / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((diff % (1000 * 60)) / 1000);

  if (hours > 0) {
    return `${hours}h ${minutes}m ${seconds}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  } else {
    return `${seconds}s`;
  }
};

const ScanResultsPage: React.FC = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanStatus[]>([]);
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [results, setResults] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchAllScans = async () => {
    try {
      const response = await api.get('/api/scans');
      setScans(response.data);
      setError(null);
    } catch (err: any) {
      console.error('Error fetching scans:', err);
      if (err.response?.status === 422) {
        const errorData = err.response.data;
        if (Array.isArray(errorData)) {
          setError(errorData.map(e => e.msg).join(', '));
        } else if (errorData.detail) {
          setError(errorData.detail);
        } else if (errorData.msg) {
          setError(errorData.msg);
        } else {
          setError('Invalid request data');
        }
      } else if (err.response?.status === 401) {
        setError('Please log in to view scans');
      } else if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else if (err.response?.data?.msg) {
        setError(err.response.data.msg);
      } else {
        setError('Failed to fetch scans');
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const fetchScanData = async () => {
    try {
      if (!scanId) {
        setError('Scan ID is required');
        return;
      }

      const status = await getScanStatus(scanId);
      setScan(status);
      setError(null);

      if (status.status === 'COMPLETED') {
        const resultsData = await getScanResults(scanId);
        setResults(resultsData);
      }
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else if (err.response?.data?.msg) {
        setError(err.response.data.msg);
      } else {
        setError('Failed to fetch scan data');
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    if (scanId) {
      fetchScanData();
    } else {
      fetchAllScans();
    }
  }, [scanId]);

  useEffect(() => {
    // Poll for updates every 5 seconds if there are running scans
    if (!scanId) {
      const hasRunningScans = scans.some(s => s.status === 'RUNNING' || s.status === 'PENDING');
      if (hasRunningScans) {
        const intervalId = setInterval(fetchAllScans, 5000);
        return () => clearInterval(intervalId);
      }
    } else if (scan?.status === 'RUNNING' || scan?.status === 'PENDING') {
      const intervalId = setInterval(fetchScanData, 5000);
      return () => clearInterval(intervalId);
    }
  }, [scanId, scans, scan?.status]);

  const handleCancelClick = (scanId: string) => {
    setSelectedScanId(scanId);
    setCancelDialogOpen(true);
  };

  const handleCancelConfirm = async () => {
    if (!selectedScanId) return;

    try {
      await api.post(`/scan/${selectedScanId}/cancel`);
      if (scanId) {
        await fetchScanData();
      } else {
        await fetchAllScans();
      }
    } catch (err: any) {
      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError('Failed to cancel scan');
      }
    } finally {
      setCancelDialogOpen(false);
      setSelectedScanId(null);
    }
  };

  const handleRefresh = () => {
    setRefreshing(true);
    if (scanId) {
      fetchScanData();
    } else {
      fetchAllScans();
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">
          {typeof error === 'string' ? error : 'An error occurred'}
        </Alert>
      </Box>
    );
  }

  if (scanId && !scan) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="info">No scan data available</Alert>
      </Box>
    );
  }

  if (!scanId) {
    return (
      <Box sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h4">
            Scan Results
          </Typography>
          <Button
            variant="outlined"
            startIcon={<Refresh />}
            onClick={handleRefresh}
            disabled={refreshing}
          >
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </Button>
        </Box>

        <Grid container spacing={3}>
          {scans.map((scan) => (
            <Grid item xs={12} key={scan.id}>
              <Card 
                sx={{ 
                  cursor: 'pointer',
                  '&:hover': {
                    boxShadow: 6
                  }
                }}
                onClick={() => navigate(`/scan/${scan.id}`)}
              >
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h6" component="div">
                      {scan.project_name}
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip
                        label={scan.status}
                        color={statusColors[scan.status as keyof typeof statusColors] as any}
                        size="small"
                      />
                      {scan.total_issues > 0 && (
                        <Chip
                          label={`${scan.total_issues} Issues`}
                          color="error"
                          size="small"
                        />
                      )}
                    </Box>
                  </Box>

                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    <Typography variant="body2" color="text.secondary">
                      Started: {scan.start_time ? formatDate(scan.start_time) : 'N/A'}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Ended: {scan.end_time ? formatDate(scan.end_time) : '-'}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Total LOC: {scan.total_loc.toLocaleString()}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Total Files: {scan.total_files}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Duration: {scan.start_time ? formatDuration(scan.start_time, scan.end_time) : '-'}
                    </Typography>
                  </Box>

                  {(scan.status === 'RUNNING' || scan.status === 'PENDING') && (
                    <>
                      <LinearProgress
                        variant="determinate"
                        value={scan.progress}
                        sx={{ mb: 1 }}
                      />
                      <Typography variant="body2" color="text.secondary">
                        Progress: {scan.progress}%
                      </Typography>
                      {scan.current_file && (
                        <Typography variant="body2" color="text.secondary">
                          Current file: {scan.current_file}
                        </Typography>
                      )}
                    </>
                  )}

                  {scan.error && (
                    <Alert severity="error" sx={{ mt: 2 }}>
                      {scan.error}
                    </Alert>
                  )}

                  {(scan.status === 'RUNNING' || scan.status === 'PENDING') && (
                    <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
                      <Button
                        variant="outlined"
                        color="error"
                        startIcon={<Cancel />}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCancelClick(scan.id);
                        }}
                      >
                        Cancel Scan
                      </Button>
                    </Box>
                  )}
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>

        <Dialog
          open={cancelDialogOpen}
          onClose={() => setCancelDialogOpen(false)}
        >
          <DialogTitle>Cancel Scan</DialogTitle>
          <DialogContent>
            <Typography>
              Are you sure you want to cancel this scan? This action cannot be undone.
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setCancelDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleCancelConfirm} color="error" variant="contained">
              Confirm
            </Button>
          </DialogActions>
        </Dialog>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4">
          Scan Results
        </Typography>
        <Button
          variant="outlined"
          startIcon={<Refresh />}
          onClick={handleRefresh}
          disabled={refreshing}
        >
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </Button>
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6" component="div">
              {scan?.project_name}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Chip
                label={scan?.status}
                color={statusColors[scan?.status as keyof typeof statusColors] as any}
                size="small"
              />
              {scan?.total_issues !== undefined && scan.total_issues > 0 && (
                <Chip
                  label={`${scan.total_issues} Issues`}
                  color="error"
                  size="small"
                />
              )}
            </Box>
          </Box>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle1" gutterBottom>
                  Progress
                </Typography>
                <LinearProgress 
                  variant="determinate" 
                  value={scan?.progress || 0} 
                  sx={{ height: 10, borderRadius: 5, mb: 1 }}
                />
                <Typography variant="body2" color="text.secondary">
                  {scan?.progress}% Complete
                </Typography>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle1" gutterBottom>
                  Current File
                </Typography>
                <Typography variant="body1">
                  {scan?.current_file || 'N/A'}
                </Typography>
              </Box>

              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle1" gutterBottom>
                  Statistics
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Files Processed
                    </Typography>
                    <Typography variant="body1">
                      {scan?.total_files}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Total Issues
                    </Typography>
                    <Typography variant="body1">
                      {scan?.total_issues}
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="text.secondary">
                      Total LOC
                    </Typography>
                    <Typography variant="body1">
                      {scan?.total_loc.toLocaleString()}
                    </Typography>
                  </Grid>
                </Grid>
              </Box>
            </Grid>

            <Grid item xs={12} md={6}>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle1" gutterBottom>
                  Timing Information
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Started: {scan?.start_time ? formatDate(scan.start_time) : 'N/A'}
                </Typography>
                {scan?.end_time && (
                  <Typography variant="body2" color="text.secondary">
                    Ended: {formatDate(scan.end_time)}
                  </Typography>
                )}
                <Typography variant="body2" color="text.secondary">
                  Duration: {scan?.start_time ? formatDuration(scan.start_time, scan.end_time) : 'N/A'}
                </Typography>
              </Box>

              {scan?.error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  {scan.error}
                </Alert>
              )}
            </Grid>
          </Grid>

          {(scan?.status === 'RUNNING' || scan?.status === 'PENDING') && (
            <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
              <Button
                variant="outlined"
                color="error"
                startIcon={<Cancel />}
                onClick={() => scan?.id && handleCancelClick(scan.id)}
              >
                Cancel Scan
              </Button>
            </Box>
          )}
        </CardContent>
      </Card>

      {scan?.status === 'COMPLETED' && results.length > 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Issues Found
            </Typography>
            <List>
              {results.map((result, index) => (
                <ListItem key={index} divider>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                        <Typography variant="subtitle1">
                          {result.file}:{result.line}
                        </Typography>
                        <Chip
                          label={result.severity}
                          color={severityColors[result.severity as keyof typeof severityColors] as any}
                          size="small"
                        />
                      </Box>
                    }
                    secondary={
                      <>
                        <Typography variant="body2" color="text.secondary">
                          {result.message}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Rule: {result.rule}
                        </Typography>
                      </>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </CardContent>
        </Card>
      )}

      <Dialog
        open={cancelDialogOpen}
        onClose={() => setCancelDialogOpen(false)}
      >
        <DialogTitle>Cancel Scan</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to cancel this scan? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCancelDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleCancelConfirm} color="error" variant="contained">
            Confirm
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ScanResultsPage; 