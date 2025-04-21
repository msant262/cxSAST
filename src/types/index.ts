export interface ScanResult {
  id: string;
  filePath: string;
  lineNumber: number;
  vulnerabilityType: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  description: string;
  codeSnippet: string;
  ruleId: string;
}

export interface ScanConfig {
  sourceType: 'GIT' | 'LOCAL';
  sourcePath: string;
  excludePaths: string[];
  rules: Rule[];
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
