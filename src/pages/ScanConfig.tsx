import React, { useState } from 'react';
import {
  Box,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  Paper,
  Grid,
} from '@mui/material';
import { ScanConfig } from '../types';

const ScanConfigPage: React.FC = () => {
  const [config, setConfig] = useState<ScanConfig>({
    sourceType: 'LOCAL',
    sourcePath: '',
    excludePaths: [],
    rules: [],
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    // TODO: Implement scan start logic
    console.log('Starting scan with config:', config);
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Configure Scan
      </Typography>
      <Paper sx={{ p: 3 }}>
        <form onSubmit={handleSubmit}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel>Source Type</InputLabel>
                <Select
                  value={config.sourceType}
                  onChange={(e) => setConfig({ ...config, sourceType: e.target.value as 'GIT' | 'LOCAL' })}
                  label="Source Type"
                >
                  <MenuItem value="LOCAL">Local Files</MenuItem>
                  <MenuItem value="GIT">Git Repository</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Source Path"
                value={config.sourcePath}
                onChange={(e) => setConfig({ ...config, sourcePath: e.target.value })}
                helperText={config.sourceType === 'GIT' ? 'Git repository URL' : 'Local directory path'}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Exclude Paths"
                value={config.excludePaths.join(',')}
                onChange={(e) => setConfig({ ...config, excludePaths: e.target.value.split(',') })}
                helperText="Comma-separated list of paths to exclude from scan"
              />
            </Grid>
            <Grid item xs={12}>
              <Button
                type="submit"
                variant="contained"
                color="primary"
                fullWidth
                size="large"
              >
                Start Scan
              </Button>
            </Grid>
          </Grid>
        </form>
      </Paper>
    </Box>
  );
};

export default ScanConfigPage; 