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
import { api } from '../services/api';

const NewScanPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0];
    if (!selectedFile) {
      return;
    }

    if (!selectedFile.name.endsWith('.zip')) {
      setError('Please select a ZIP file');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      const projectName = selectedFile.name.replace('.zip', '');
      console.log('Uploading file:', selectedFile.name);
      console.log('Project name:', projectName);
      
      formData.append('project_name', projectName);
      formData.append('file', selectedFile);

      console.log('FormData entries:');
      for (const [key, value] of formData.entries()) {
        console.log(key, ':', value);
      }

      const response = await api.post('/api/scan', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      console.log('Upload response:', response.data);
      navigate('/scan-status');
    } catch (err) {
      console.error('Upload error:', err);
      if (err instanceof Error) {
        setError(err.message);
      } else if (typeof err === 'object' && err !== null && 'response' in err) {
        const errorResponse = err as { response?: { data?: { detail?: string }, status?: number, statusText?: string } };
        console.error('Error response:', {
          status: errorResponse.response?.status,
          statusText: errorResponse.response?.statusText,
          detail: errorResponse.response?.data?.detail
        });
        setError(errorResponse.response?.data?.detail || 'Failed to upload file');
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
        Upload de Arquivo ZIP
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Card>
        <CardContent sx={{ textAlign: 'center' }}>
          <label htmlFor="file-input">
            <input
              type="file"
              accept=".zip"
              onChange={handleFileChange}
              style={{ display: 'none' }}
              id="file-input"
            />
            <Button
              variant="contained"
              component="span"
              startIcon={loading ? <CircularProgress size={20} /> : <FolderOpen />}
              disabled={loading}
              sx={{ mt: 2 }}
            >
              {loading ? 'Enviando...' : 'Selecionar Arquivo ZIP'}
            </Button>
          </label>
        </CardContent>
      </Card>
    </Box>
  );
};

export default NewScanPage; 