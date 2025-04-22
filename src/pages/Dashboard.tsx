import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  useTheme,
  Card,
  CardContent,
  Divider,
  IconButton,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  Link,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  CircularProgress,
  Alert,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  ListItemIcon,
} from '@mui/material';
import {
  Error as CriticalIcon,
  Warning as HighIcon,
  Info as MediumIcon,
  CheckCircle as LowIcon,
  BugReport as IssueIcon,
  Shield as VulnIcon,
  HelpOutline as HelpIcon,
  OpenInNew as OpenInNewIcon,
  PlayArrow,
  Refresh,
  Security,
  Assessment,
  Timeline,
  LowPriority,
  Folder,
} from '@mui/icons-material';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip as ChartTooltip,
  Legend,
} from 'chart.js';
import axios from 'axios';
import { API_BASE_URL } from '../services/api';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  ChartTooltip,
  Legend
);

interface MetricCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  color?: string;
  helpText?: string;
}

const MetricCard: React.FC<MetricCardProps> = ({ title, value, icon, color, helpText }) => {
  const theme = useTheme();
  
  return (
    <Card 
      sx={{ 
        height: '100%',
        backgroundColor: color ? `${color}15` : theme.palette.background.paper,
        borderLeft: color ? `4px solid ${color}` : 'none',
        '&:hover': {
          boxShadow: 3,
          transform: 'translateY(-2px)',
          transition: 'all 0.3s ease-in-out',
        },
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
          <Typography 
            variant="subtitle1" 
            color="textSecondary" 
            sx={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: 1,
              fontSize: '1rem',
              fontWeight: 500,
            }}
          >
            {title}
            {helpText && (
              <Tooltip title={helpText}>
                <IconButton size="small">
                  <HelpIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            )}
          </Typography>
          <Box sx={{ color: color || theme.palette.primary.main }}>
            {React.cloneElement(icon as React.ReactElement, { fontSize: 'large' })}
          </Box>
        </Box>
        <Typography variant="h3" component="div" sx={{ fontWeight: 'bold', fontSize: '2.5rem' }}>
          {value}
        </Typography>
      </CardContent>
    </Card>
  );
};

interface Vulnerability {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  score: number;
  issue: string;
  cve: string;
  cwe: string;
  project: string;
  exploitMaturity: string;
  fixability: string;
  introduced: string;
  product: string;
}

const severityColors = {
  CRITICAL: '#dc3545',
  HIGH: '#ff9800',
  MEDIUM: '#fb8c00',
  LOW: '#757575',
};

const severityIcons = {
  CRITICAL: <CriticalIcon fontSize="small" />,
  HIGH: <HighIcon fontSize="small" />,
  MEDIUM: <MediumIcon fontSize="small" />,
  LOW: <LowIcon fontSize="small" />,
};

const VulnerabilityTable: React.FC<{ vulnerabilities: Vulnerability[] }> = ({ vulnerabilities }) => {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(5);
  const [sortBy, setSortBy] = useState('severity');

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  return (
    <Paper sx={{ mt: 4, p: 3, borderRadius: 2 }}>
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        mb: 3,
        gap: 2,
      }}>
        <Typography variant="h6" sx={{ fontSize: '1.25rem', fontWeight: 600 }}>
          Issue Details
        </Typography>
        <FormControl size="small" sx={{ minWidth: 200 }}>
          <InputLabel>Sort by</InputLabel>
          <Select
            value={sortBy}
            label="Sort by"
            onChange={(e) => setSortBy(e.target.value)}
          >
            <MenuItem value="severity">Severity</MenuItem>
            <MenuItem value="score">Score</MenuItem>
            <MenuItem value="introduced">Date</MenuItem>
          </Select>
        </FormControl>
      </Box>
      <TableContainer>
        <Table size="medium" sx={{ minWidth: 1200 }}>
          <TableHead>
            <TableRow>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>SEVERITY</TableCell>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>SCORE</TableCell>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>ISSUE</TableCell>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>CVE</TableCell>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>CWE</TableCell>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>PROJECT</TableCell>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>EXPLOIT MATURITY</TableCell>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>FIXABILITY</TableCell>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>INTRODUCED</TableCell>
              <TableCell sx={{ fontWeight: 600, py: 2 }}>PRODUCT</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {/* Sample data row */}
            <TableRow hover>
              <TableCell sx={{ py: 2 }}>
                <Chip
                  icon={severityIcons.HIGH}
                  label="HIGH"
                  size="small"
                  sx={{
                    backgroundColor: `${severityColors.HIGH}15`,
                    color: severityColors.HIGH,
                    '& .MuiChip-icon': { color: 'inherit' },
                    px: 1,
                  }}
                />
              </TableCell>
              <TableCell sx={{ py: 2 }}>1000</TableCell>
              <TableCell sx={{ py: 2 }}>
                <Link 
                  href="#" 
                  color="primary" 
                  sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: 0.5,
                    textDecoration: 'none',
                    '&:hover': {
                      textDecoration: 'underline',
                    },
                  }}
                >
                  Use After Free
                  <OpenInNewIcon fontSize="small" />
                </Link>
              </TableCell>
              <TableCell sx={{ py: 2 }}>
                <Link href="#" color="primary">CVE-2019-5786</Link>
              </TableCell>
              <TableCell sx={{ py: 2 }}>
                <Link href="#" color="primary">CWE-416</Link>
              </TableCell>
              <TableCell sx={{ py: 2, maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                Nova-8/damn-vulnerable-js-sca:web-app/package.json
              </TableCell>
              <TableCell sx={{ py: 2 }}>Mature</TableCell>
              <TableCell sx={{ py: 2 }}>Fixable</TableCell>
              <TableCell sx={{ py: 2 }}>Mar 26, 2025</TableCell>
              <TableCell sx={{ py: 2 }}>Snyk Open Source</TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </TableContainer>
      <TablePagination
        rowsPerPageOptions={[5, 10, 25]}
        component="div"
        count={vulnerabilities.length || 1}
        rowsPerPage={rowsPerPage}
        page={page}
        onPageChange={handleChangePage}
        onRowsPerPageChange={handleChangeRowsPerPage}
        sx={{ mt: 2 }}
      />
    </Paper>
  );
};

interface ScanStats {
  totalScans: number;
  completedScans: number;
  runningScans: number;
  failedScans: number;
  cancelledScans: number;
  pendingScans: number;
  averageDuration: string;
  totalVulnerabilities: number;
  highSeverity: number;
  mediumSeverity: number;
  lowSeverity: number;
}

interface ProjectScan {
  scanId: string;
  projectName: string;
  status: string;
  progress: number;
  startTime: string;
  endTime?: string;
  error?: string;
  currentFile?: string;
}

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
  });
};

const formatDuration = (startTime: string, endTime?: string) => {
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

const calculateStats = (scans: ProjectScan[]): ScanStats => {
  const completedScans = scans.filter(s => s.status === 'COMPLETED');
  const durations = completedScans.map(s => {
    const start = new Date(s.startTime);
    const end = s.endTime ? new Date(s.endTime) : new Date();
    return end.getTime() - start.getTime();
  });

  const averageDurationMs = durations.length > 0
    ? durations.reduce((a, b) => a + b, 0) / durations.length
    : 0;

  const hours = Math.floor(averageDurationMs / (1000 * 60 * 60));
  const minutes = Math.floor((averageDurationMs % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((averageDurationMs % (1000 * 60)) / 1000);

  return {
    totalScans: scans.length,
    completedScans: completedScans.length,
    runningScans: scans.filter(s => s.status === 'RUNNING').length,
    failedScans: scans.filter(s => s.status === 'FAILED').length,
    cancelledScans: scans.filter(s => s.status === 'CANCELLED').length,
    pendingScans: scans.filter(s => s.status === 'PENDING').length,
    averageDuration: `${hours}h ${minutes}m ${seconds}s`,
    totalVulnerabilities: 0, // TODO: Implement when vulnerability data is available
    highSeverity: 0,
    mediumSeverity: 0,
    lowSeverity: 0,
  };
};

interface DashboardStats {
  total_scans: number;
  total_vulnerabilities: number;
  vulnerability_counts: {
    CRITICAL: number;
    HIGH: number;
    MEDIUM: number;
    LOW: number;
    INFORMATIONAL: number;
  };
  recent_scans: Array<{
    id: string;
    project_name: string;
    status: string;
    start_time: string;
    total_issues: number;
  }>;
  top_projects: Array<{
    name: string;
    scan_count: number;
    vulnerability_count: number;
  }>;
  daily_scan_counts: Array<{
    date: string;
    count: number;
  }>;
  scan_status_counts: {
    completed: number;
    running: number;
    failed: number;
    cancelled: number;
    pending: number;
  };
  average_duration: string;
  top_vulnerabilities: Array<{
    rule: string;
    severity: string;
    count: number;
  }>;
}

const Dashboard: React.FC = () => {
  const theme = useTheme();
  const [scans, setScans] = useState<ProjectScan[]>([]);
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchScans = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/dashboard/stats`);
      setScans(response.data.recent_scans);
      setStats(response.data);
      setError(null);
    } catch (err) {
      if (axios.isAxiosError(err)) {
        setError(err.response?.data?.detail || 'Failed to fetch dashboard data');
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
  }, []);

  useEffect(() => {
    // Poll for updates every 30 seconds
    const intervalId = setInterval(fetchScans, 30000);
    return () => clearInterval(intervalId);
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchScans();
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <CircularProgress />
      </Box>
    );
  }

  const successRate = stats?.scan_status_counts?.completed && stats?.total_scans
    ? Math.round((stats.scan_status_counts.completed / stats.total_scans) * 100)
    : 0;

  const chartData = {
    labels: stats?.daily_scan_counts?.map(item => item.date) || [],
    datasets: [
      {
        label: 'Scans',
        data: stats?.daily_scan_counts?.map(item => item.count) || [],
        fill: false,
        borderColor: 'rgb(75, 192, 192)',
        tension: 0.1
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 1
        }
      }
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: '1400px', margin: '0 auto' }}>
      {/* Header */}
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
          Dashboard
        </Typography>
        <Button
          variant="outlined"
          startIcon={<Refresh />}
          onClick={handleRefresh}
          disabled={refreshing}
          sx={{ minWidth: '120px' }}
        >
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {stats && (
        <Grid container spacing={3}>
          {/* Overview Cards */}
          <Grid item xs={12}>
            <Grid container spacing={3}>
              <Grid item xs={12} sm={6} md={3}>
                <Card sx={{ height: '100%' }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                      <IssueIcon color="primary" />
                      <Typography variant="h6">Total Scans</Typography>
                    </Box>
                    <Typography variant="h4" sx={{ fontWeight: 600 }}>
                      {stats?.total_scans || 0}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} sm={6} md={3}>
                <Card sx={{ height: '100%' }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                      <LowIcon color="success" />
                      <Typography variant="h6">Completed</Typography>
                    </Box>
                    <Typography variant="h4" sx={{ fontWeight: 600 }}>
                      {stats?.scan_status_counts?.completed || 0}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} sm={6} md={3}>
                <Card sx={{ height: '100%' }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                      <PlayArrow color="primary" />
                      <Typography variant="h6">Running</Typography>
                    </Box>
                    <Typography variant="h4" sx={{ fontWeight: 600 }}>
                      {stats?.scan_status_counts?.running || 0}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>

              <Grid item xs={12} sm={6} md={3}>
                <Card sx={{ height: '100%' }}>
                  <CardContent>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                      <CriticalIcon color="error" />
                      <Typography variant="h6">Failed</Typography>
                    </Box>
                    <Typography variant="h4" sx={{ fontWeight: 600 }}>
                      {(stats?.scan_status_counts?.failed || 0) + (stats?.scan_status_counts?.cancelled || 0)}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Grid>

          {/* Main Content */}
          <Grid item xs={12} md={8}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ mb: 3 }}>
                  Scans per Day (Last 30 Days)
                </Typography>
                <Box sx={{ height: 300 }}>
                  <Line data={chartData} options={chartOptions} />
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ mb: 3 }}>
                  Vulnerability Distribution
                </Typography>
                <List dense>
                  {stats?.vulnerability_counts && Object.entries(stats.vulnerability_counts).map(([severity, count]) => (
                    <ListItem 
                      key={severity}
                      sx={{ 
                        py: 1,
                        '&:not(:last-child)': {
                          borderBottom: '1px solid',
                          borderColor: 'divider'
                        }
                      }}
                    >
                      <ListItemText 
                        primary={
                          <Typography variant="body1" sx={{ fontWeight: 500 }}>
                            {severity}
                          </Typography>
                        } 
                      />
                      <ListItemSecondaryAction>
                        <Chip 
                          label={count} 
                          color={severity === 'CRITICAL' ? 'error' : 
                                 severity === 'HIGH' ? 'warning' : 
                                 severity === 'MEDIUM' ? 'info' : 
                                 severity === 'LOW' ? 'success' : 'default'} 
                          size="small" 
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          {/* Top 10 Most Common Vulnerabilities */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3 }}>
                  <Security color="primary" />
                  <Typography variant="h6">Top Vulnerabilities by Severity</Typography>
                </Box>
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => {
                  const severityVulnerabilities = stats?.top_vulnerabilities?.filter(v => v.severity === severity) || [];
                  if (severityVulnerabilities.length === 0) return null;
                  
                  return (
                    <Box key={severity} sx={{ mb: 3 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                        <Chip
                          label={severity}
                          size="small"
                          color={
                            severity === 'CRITICAL' ? 'error' :
                            severity === 'HIGH' ? 'warning' :
                            severity === 'MEDIUM' ? 'info' :
                            severity === 'LOW' ? 'success' : 'default'
                          }
                        />
                        <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
                          {severityVulnerabilities.length} {severityVulnerabilities.length === 1 ? 'Vulnerability' : 'Vulnerabilities'}
                        </Typography>
                      </Box>
                      <TableContainer>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell sx={{ fontWeight: 600 }}>Vulnerability</TableCell>
                              <TableCell sx={{ fontWeight: 600 }}>Count</TableCell>
                              <TableCell sx={{ fontWeight: 600 }}>Percentage</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {severityVulnerabilities.map((vuln) => {
                              const percentage = ((vuln.count / stats.total_vulnerabilities) * 100).toFixed(1);
                              return (
                                <TableRow key={vuln.rule}>
                                  <TableCell>
                                    <Typography variant="body1">
                                      {vuln.rule}
                                    </Typography>
                                  </TableCell>
                                  <TableCell>
                                    <Typography variant="body1">
                                      {vuln.count}
                                    </Typography>
                                  </TableCell>
                                  <TableCell>
                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                      <Typography variant="body1">
                                        {percentage}%
                                      </Typography>
                                      <Box sx={{ flexGrow: 1, height: 8, bgcolor: 'divider', borderRadius: 1 }}>
                                        <Box 
                                          sx={{ 
                                            height: '100%', 
                                            bgcolor: 
                                              severity === 'CRITICAL' ? 'error.main' :
                                              severity === 'HIGH' ? 'warning.main' :
                                              severity === 'MEDIUM' ? 'info.main' :
                                              severity === 'LOW' ? 'success.main' : 'default',
                                            borderRadius: 1,
                                            width: `${percentage}%`
                                          }} 
                                        />
                                      </Box>
                                    </Box>
                                  </TableCell>
                                </TableRow>
                              );
                            })}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    </Box>
                  );
                })}
              </CardContent>
            </Card>
          </Grid>

          {/* Top Projects */}
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ mb: 3 }}>
                  Top Projects
                </Typography>
                <List>
                  {stats?.top_projects?.map((project) => (
                    <ListItem 
                      key={project.name}
                      sx={{ 
                        py: 2,
                        '&:not(:last-child)': {
                          borderBottom: '1px solid',
                          borderColor: 'divider'
                        }
                      }}
                    >
                      <ListItemText 
                        primary={
                          <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
                            {project.name}
                          </Typography>
                        }
                        secondary={`${project.scan_count} scans, ${project.vulnerability_count} vulnerabilities`}
                      />
                      <ListItemSecondaryAction>
                        <Chip 
                          label={project.vulnerability_count} 
                          color="error" 
                          size="small" 
                        />
                      </ListItemSecondaryAction>
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          {/* Recent Activity and Statistics */}
          <Grid item xs={12} md={6}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ mb: 3 }}>
                  Recent Activity
                </Typography>
                <List>
                  {stats?.recent_scans?.slice(0, 5).map((scan) => (
                    <React.Fragment key={scan.id}>
                      <ListItem sx={{ py: 2 }}>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <Typography variant="subtitle1" sx={{ fontWeight: 500 }}>
                                {scan.project_name}
                              </Typography>
                              <Chip
                                label={scan.status}
                                color={statusColors[scan.status as keyof typeof statusColors] as any}
                                size="small"
                              />
                            </Box>
                          }
                          secondary={
                            <Box sx={{ mt: 1 }}>
                              <Typography variant="body2" color="text.secondary">
                                Started: {formatDate(scan.start_time)}
                              </Typography>
                              {scan.total_issues > 0 && (
                                <Typography variant="body2" color="text.secondary">
                                  Issues: {scan.total_issues}
                                </Typography>
                              )}
                            </Box>
                          }
                        />
                      </ListItem>
                      <Divider />
                    </React.Fragment>
                  ))}
                </List>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            <Card sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ mb: 3 }}>
                  Statistics
                </Typography>
                <List>
                  <ListItem sx={{ py: 2 }}>
                    <ListItemText
                      primary="Average Scan Duration"
                      secondary={stats?.average_duration || 'N/A'}
                    />
                  </ListItem>
                  <Divider />
                  <ListItem sx={{ py: 2 }}>
                    <ListItemText
                      primary="Pending Scans"
                      secondary={stats?.scan_status_counts?.pending || 0}
                    />
                  </ListItem>
                  <Divider />
                  <ListItem sx={{ py: 2 }}>
                    <ListItemText
                      primary="Success Rate"
                      secondary={`${successRate}%`}
                    />
                  </ListItem>
                </List>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}
    </Box>
  );
};

export default Dashboard; 