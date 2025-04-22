import * as React from 'react';
import { useState } from 'react';
import {
  Box,
  Button,
  Typography,
  Card,
  CardContent,
  Alert,
  CircularProgress,
} from '@mui/material';
import { Upload as UploadIcon } from '@mui/icons-material';
import { api } from '../services/api';
import { useNavigate } from 'react-router-dom';

const ScanConfigPage: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    event.preventDefault();
    const file = event.target.files?.[0];
    if (!file) {
      console.log('No file selected');
      return;
    }

    console.log('Starting file upload:', file.name);
    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);

      console.log('Sending request to backend...');
      const response = await api.post('/scan', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'Cache-Control': 'no-cache'
        }
      });

      console.log('Response received:', response.data);
      
      if (!response.data || !response.data.scanId) {
        throw new Error('Invalid response from server: missing scanId');
      }
      
      const scanId = response.data.scanId;
      console.log('Navigating to scan status with ID:', scanId);
      navigate(`/scan-status/${scanId}`, { replace: true });
      
    } catch (err) {
      console.error('Error during file upload:', err);
      if (err.response?.data?.detail) {
        setError(err.response.data.detail);
      } else {
        setError('Failed to upload file');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 600, margin: '0 auto' }}>
      <Typography variant="h4" gutterBottom align="center">
        Upload ZIP File
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Card>
        <CardContent sx={{ textAlign: 'center' }}>
          <input
            type="file"
            accept=".zip"
            onChange={handleFileUpload}
            style={{ display: 'none' }}
            id="file-input"
            disabled={loading}
          />
          <label htmlFor="file-input">
            <Button
              variant="contained"
              component="span"
              startIcon={loading ? <CircularProgress size={20} /> : <UploadIcon />}
              disabled={loading}
              sx={{ mt: 2 }}
            >
              {loading ? 'Uploading...' : 'Select ZIP File'}
            </Button>
          </label>
        </CardContent>
      </Card>
    </Box>
  );
};

export default ScanConfigPage; 