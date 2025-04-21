import React from 'react';
import {
  Box,
  Typography,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
} from '@mui/material';
import { ScanResult } from '../types';

interface ScanResultsProps {
  results: ScanResult[];
}

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'CRITICAL':
      return 'error';
    case 'HIGH':
      return 'warning';
    case 'MEDIUM':
      return 'info';
    case 'LOW':
      return 'success';
    default:
      return 'default';
  }
};

const ScanResultsPage: React.FC<ScanResultsProps> = ({ results }) => {
  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Scan Results
      </Typography>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>File</TableCell>
              <TableCell>Line</TableCell>
              <TableCell>Vulnerability</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Description</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {results.map((result) => (
              <TableRow key={result.id}>
                <TableCell>{result.filePath}</TableCell>
                <TableCell>{result.lineNumber}</TableCell>
                <TableCell>{result.vulnerabilityType}</TableCell>
                <TableCell>
                  <Chip
                    label={result.severity}
                    color={getSeverityColor(result.severity)}
                    size="small"
                  />
                </TableCell>
                <TableCell>{result.description}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default ScanResultsPage; 