import React, { useState } from 'react';
import {
  Box,
  Typography,
  Button,
  Alert,
  CircularProgress,
  Card,
  CardContent,
} from '@mui/material';
import { FolderOpen } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const NewScanPage: React.FC = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setLoading(true);
    setError(null);

    try {
      console.log('Uploading file:', file.name);
      
      const formData = new FormData();
      formData.append('file', file);

      const response = await axios.post('http://localhost:8000/api/scan', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'Cache-Control': 'no-cache'
        }
      });

      console.log('Response from backend:', response.data);
      
      if (!response.data || !response.data.scanId) {
        throw new Error('Invalid response from server');
      }
      
      navigate(`/scan-status/${response.data.scanId}`);
    } catch (err) {
      console.error('Error uploading file:', err);
      if (axios.isAxiosError(err)) {
        setError(err.response?.data?.detail || 'Failed to upload file');
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
              startIcon={loading ? <CircularProgress size={20} /> : <FolderOpen />}
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

export default NewScanPage; 