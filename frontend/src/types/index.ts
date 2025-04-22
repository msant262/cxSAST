export interface Vulnerability {
  type: string;
  severity: string;
  line: number;
  description: string;
}

export interface ScanResult {
  file_name: string;
  vulnerabilities: Vulnerability[];
  severity: string;
  line_number: number;
  description: string;
}

export interface ScanConfig {
  sourceType: 'GIT' | 'LOCAL';
  sourcePath: string;
  projectName: string;
  excludePaths: string[];
  rules: string[];
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  pattern: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  enabled: boolean;
}

export interface ScanProgress {
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  progress: number;
  currentFile: string;
  totalFiles: number;
}
