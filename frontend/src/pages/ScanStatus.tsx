import React, { useState, useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  Box,
  Typography,
  CircularProgress,
  Paper,
  Grid,
  Button,
  Alert,
  LinearProgress,
  Chip,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  HourglassEmpty as HourglassEmptyIcon,
  Refresh as RefreshIcon,
  Delete as DeleteIcon,
  Cancel as CancelIcon,
} from '@mui/icons-material';
import { api } from '../services/api';

interface Scan {
  id: number;
  project_name: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  created_at: string;
  progress?: number;
  error?: string;
}

const ScanStatus: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const navigate = useNavigate();
  const { scanId } = useParams<{ scanId: string }>();

  const fetchScans = async () => {
    try {
      const response = await api.get('/api/scans');
      setScans(response.data);
      setError(null);
    } catch (err) {
      console.error('Error fetching scans:', err);
      setError('Failed to fetch scans. Please try again.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRefresh = () => {
    setRefreshing(true);
    fetchScans();
  };

  const handleDelete = async (id: number) => {
    try {
      await api.delete(`/api/scan/${id}`);
      setScans(scans.filter(scan => scan.id !== id));
    } catch (err) {
      console.error('Error deleting scan:', err);
      setError('Failed to delete scan. Please try again.');
    }
  };

  const handleCancel = async (id: number) => {
    try {
      await api.post(`/api/scan/${id}/cancel`);
      setScans(scans.map(scan => 
        scan.id === id ? { ...scan, status: 'failed', error: 'Scan cancelled by user' } : scan
      ));
    } catch (err) {
      console.error('Error cancelling scan:', err);
      setError('Failed to cancel scan. Please try again.');
    }
  };

  useEffect(() => {
    fetchScans();
  }, []);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="200px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box p={3}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">Scan Status</Typography>
        <Button
          variant="contained"
          color="primary"
          startIcon={<RefreshIcon />}
          onClick={handleRefresh}
          disabled={refreshing}
        >
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        {scans.map((scan) => (
          <Grid item xs={12} key={scan.id}>
            <Paper elevation={2} sx={{ p: 3 }}>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6">{scan.project_name}</Typography>
                <Box>
                  <Tooltip title="Cancel Scan">
                    <IconButton
                      onClick={() => handleCancel(scan.id)}
                      disabled={scan.status !== 'processing'}
                      color="error"
                    >
                      <CancelIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Delete Scan">
                    <IconButton
                      onClick={() => handleDelete(scan.id)}
                      disabled={scan.status === 'processing'}
                      color="error"
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Tooltip>
                </Box>
              </Box>

              <Box display="flex" alignItems="center" mb={2}>
                <Chip
                  icon={
                    scan.status === 'completed' ? (
                      <CheckCircleIcon />
                    ) : scan.status === 'failed' ? (
                      <ErrorIcon />
                    ) : (
                      <HourglassEmptyIcon />
                    )
                  }
                  label={scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                  color={
                    scan.status === 'completed'
                      ? 'success'
                      : scan.status === 'failed'
                      ? 'error'
                      : 'warning'
                  }
                  sx={{ mr: 2 }}
                />
                <Typography variant="body2" color="textSecondary">
                  Started: {new Date(scan.created_at).toLocaleString()}
                </Typography>
              </Box>

              {scan.status === 'processing' && (
                <Box>
                  <LinearProgress
                    variant="determinate"
                    value={scan.progress || 0}
                    sx={{ mb: 1, height: 10, borderRadius: 5 }}
                  />
                  <Typography variant="body2" color="textSecondary">
                    Progress: {scan.progress || 0}%
                  </Typography>
                </Box>
              )}

              {scan.status === 'failed' && scan.error && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  {scan.error}
                </Alert>
              )}

              {scan.status === 'completed' && (
                <Button
                  variant="contained"
                  color="primary"
                  onClick={() => navigate(`/scan/${scan.id}`)}
                  sx={{ mt: 2 }}
                >
                  View Results
                </Button>
              )}
            </Paper>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

export default ScanStatus; 