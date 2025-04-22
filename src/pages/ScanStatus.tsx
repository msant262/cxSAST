import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Box, Typography, LinearProgress, Paper, Button, Alert, Grid, Card, CardContent, Chip, CircularProgress, List, ListItem, ListItemText, ListItemSecondaryAction, IconButton, Dialog, DialogTitle, DialogContent, DialogContentText, DialogActions, Tooltip } from '@mui/material';
import { Cancel, Refresh, PlayArrow, Stop, Timer, Visibility, Delete } from '@mui/icons-material';
import axios from 'axios';
import { getScanStatus, ScanStatus, API_BASE_URL } from '../services/api';

const statusColors = {
  COMPLETED: 'success',
  FAILED: 'error',
  RUNNING: 'primary',
  PENDING: 'default',
  CANCELLED: 'error',
} as const;

const formatDate = (dateString: string) => {
  const date = new Date(dateString);
  return date.toLocaleString('pt-BR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
};

const formatDuration = (startTime: string, endTime: string | null | undefined) => {
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

const ScanStatusPage: React.FC = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scans, setScans] = useState<ScanStatus[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const fetchScans = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/scans`);
      setScans(response.data);
      setError(null);
    } catch (err) {
      if (axios.isAxiosError(err)) {
        setError(err.response?.data?.detail || 'Failed to fetch scans');
      } else {
        setError('An unexpected error occurred');
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleViewResults = (scanId: string) => {
    navigate(`/scan/${scanId}`);
  };

  const handleCancelClick = (scanId: string) => {
    setSelectedScanId(scanId);
    setCancelDialogOpen(true);
  };

  const handleCancelConfirm = async () => {
    if (!selectedScanId) return;

    try {
      await axios.post(`${API_BASE_URL}/scan/${selectedScanId}/cancel`);
      await fetchScans();
    } catch (err) {
      if (axios.isAxiosError(err)) {
        setError(err.response?.data?.detail || 'Failed to cancel scan');
      } else {
        setError('An unexpected error occurred while cancelling scan');
      }
    } finally {
      setCancelDialogOpen(false);
      setSelectedScanId(null);
    }
  };

  const handleRefresh = () => {
    setRefreshing(true);
    fetchScans();
  };

  const handleDelete = async () => {
    if (!selectedScanId) return;
    
    setDeleting(true);
    try {
      await axios.delete(`${API_BASE_URL}/scan/${selectedScanId}`);
      if (scanId === selectedScanId) {
        navigate('/dashboard');
      } else {
        fetchScans();
      }
    } catch (err) {
      setError('Failed to delete scan');
      console.error('Error deleting scan:', err);
    } finally {
      setDeleting(false);
      setDeleteDialogOpen(false);
      setSelectedScanId(null);
    }
  };

  const handleDeleteClick = (scanId: string) => {
    setSelectedScanId(scanId);
    setDeleteDialogOpen(true);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'RUNNING':
        return <PlayArrow color="primary" />;
      case 'COMPLETED':
        return <Stop color="success" />;
      case 'FAILED':
        return <Stop color="error" />;
      case 'CANCELLED':
        return <Stop color="error" />;
      default:
        return <Stop color="action" />;
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
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        mb: 4,
        borderBottom: '1px solid',
        borderColor: 'divider',
        pb: 2
      }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          Scan Status
        </Typography>
      </Box>

      <List>
        {scans.map((scan) => (
          <ListItem
            key={scan.id}
            component={Card}
            sx={{ mb: 2 }}
          >
            <CardContent sx={{ width: '100%' }}>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    {getStatusIcon(scan.status)}
                    <Typography variant="h6">{scan.project_name}</Typography>
                    <Chip
                      label={scan.status}
                      color={statusColors[scan.status as keyof typeof statusColors] as any}
                      size="small"
                    />
                  </Box>

                  <Box sx={{ mb: 2 }}>
                    <Typography variant="subtitle1" gutterBottom>
                      Progress
                    </Typography>
                    <LinearProgress 
                      variant="determinate" 
                      value={scan.progress} 
                      sx={{ height: 10, borderRadius: 5, mb: 1 }}
                    />
                    <Typography variant="body2" color="text.secondary">
                      {scan.progress}% Complete
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
                          {scan.total_files}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Total Issues
                        </Typography>
                        <Typography variant="body1">
                          {scan.total_issues}
                        </Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="body2" color="text.secondary">
                          Total LOC
                        </Typography>
                        <Typography variant="body1">
                          {scan.total_loc.toLocaleString()}
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
                      Started: {scan.start_time ? formatDate(scan.start_time) : 'N/A'}
                    </Typography>
                    {scan.end_time && (
                      <Typography variant="body2" color="text.secondary">
                        Ended: {formatDate(scan.end_time)}
                      </Typography>
                    )}
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
                      <Timer fontSize="small" color="action" />
                      <Typography variant="body2" color="text.secondary">
                        Duration: {scan.start_time ? formatDuration(scan.start_time, scan.end_time) : 'N/A'}
                      </Typography>
                    </Box>
                  </Box>

                  {scan.error && (
                    <Alert severity="error" sx={{ mb: 2 }}>
                      {scan.error}
                    </Alert>
                  )}
                </Grid>
              </Grid>

              <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                {scan.status === 'COMPLETED' && (
                  <Button
                    variant="contained"
                    color="primary"
                    startIcon={<Visibility />}
                    onClick={() => handleViewResults(scan.id)}
                  >
                    View Results
                  </Button>
                )}

                {(scan.status === 'RUNNING' || scan.status === 'PENDING') && (
                  <Button
                    variant="outlined"
                    color="error"
                    startIcon={<Cancel />}
                    onClick={() => handleCancelClick(scan.id)}
                  >
                    Cancel Scan
                  </Button>
                )}

                <Button
                  variant="outlined"
                  color="error"
                  startIcon={<Delete />}
                  onClick={() => handleDeleteClick(scan.id)}
                  disabled={deleting}
                >
                  Delete Scan
                </Button>
              </Box>
            </CardContent>
          </ListItem>
        ))}
      </List>

      <Dialog
        open={deleteDialogOpen}
        onClose={() => setDeleteDialogOpen(false)}
      >
        <DialogTitle>Delete Scan</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to delete this scan? This action cannot be undone and will permanently delete all scan data and results.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)} disabled={deleting}>
            Cancel
          </Button>
          <Button 
            onClick={handleDelete} 
            color="error" 
            disabled={deleting}
            startIcon={deleting ? <CircularProgress size={20} /> : <Delete />}
          >
            {deleting ? 'Deleting...' : 'Delete'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ScanStatusPage; 