import axios from 'axios';

export const API_BASE_URL = 'http://localhost:8000/api';

// Types
export interface ScanDetails {
  scanId: string;
  projectName: string;
  status: string;
  startTime: string;
  endTime?: string;
  progress: number;
  currentFile?: string;
  totalFiles: number;
  totalIssues: number;
  totalLoc?: number;
  error?: string;
}

export interface VulnerabilityDetails {
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
  sourceCode?: {
    snippet: string;
    startLine: number;
    endLine: number;
    highlightedLines: number[];
    totalLines: number;
    fullContent: string;
  };
  remediation?: {
    description: string;
    steps: string[];
    references: string[];
  };
}

export interface ScanResult {
  id: string;
  file: string;
  line: number;
  rule: string;
  message: string;
  severity: string;
  isIgnored?: boolean;
  isFalsePositive?: boolean;
  details?: VulnerabilityDetails;
}

export interface ScanStatus {
  id: string;
  project_name: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'ERROR' | 'CANCELLED';
  start_time: string | null;
  end_time: string | null;
  progress: number;
  current_file: string | null;
  total_files: number;
  total_issues: number;
  total_loc: number;
  error: string | null;
}

// API Functions
export const getAllScans = async (): Promise<ScanDetails[]> => {
  const response = await axios.get(`${API_BASE_URL}/scans`);
  return response.data;
};

export const getScanDetails = async (scanId: string): Promise<ScanDetails> => {
  const response = await axios.get(`${API_BASE_URL}/scan/${scanId}`);
  return response.data;
};

export const getScanResults = async (scanId: string): Promise<ScanResult[]> => {
  const response = await axios.get(`${API_BASE_URL}/scan/${scanId}/vulnerabilities`);
  return response.data;
};

export const uploadScanFile = async (file: File): Promise<{ scanId: string }> => {
  const formData = new FormData();
  formData.append('file', file);
  const response = await axios.post(`${API_BASE_URL}/scan`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
};

export const getSourceCode = async (file: string, line: number): Promise<{
  snippet: string;
  startLine: number;
  endLine: number;
  highlightedLines: number[];
  fullContent: string;
  totalLines: number;
}> => {
  const response = await axios.get(`${API_BASE_URL}/scan/source`, {
    params: { file, line },
  });
  return response.data;
};

export const markVulnerabilityAsIgnored = async (vulnerabilityId: string, isIgnored: boolean): Promise<void> => {
  await axios.patch(`${API_BASE_URL}/vulnerability/${vulnerabilityId}/ignore`, {
    isIgnored,
  });
};

export const markVulnerabilityAsFalsePositive = async (vulnerabilityId: string, isFalsePositive: boolean): Promise<void> => {
  await axios.patch(`${API_BASE_URL}/vulnerability/${vulnerabilityId}/false-positive`, {
    isFalsePositive,
  });
};

export const getScanStatus = async (scanId: string): Promise<ScanStatus> => {
  const response = await axios.get(`${API_BASE_URL}/scan/${scanId}`);
  return response.data;
};
