import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';
import { CryptoService } from './crypto.service';

// Interfaces pour les données de l'application
export interface Analysis {
  id: number;
  created_at: string;
  source_type: string;
  source_path: string;
  server_ip: string;
  stats: {
    errors: number;
    warnings: number;
    info: number;
    total: number;
  };
  segments: any;
  meta: any;
  severity_counts?: {
    high: number;
    medium: number;
    low: number;
  };
  ai_score: number;
  ai_status: string;
  ai_menaces: number;
  file_path?: string; // Ajout de la propriété optionnelle
}

export interface DashboardSummary {
  total_audits: number;
  active_servers: number;
  critical_threats: number;
  system_health: number;
}

export interface StatsResponse {
  status: string;
  labels: string[];
  critique: number[];
  avertissement: number[];
  info: number[];
  total_logs: number;
  total_errors: number;
  total_warnings: number;
  summary: DashboardSummary;
  analysis_data?: Analysis | null;
  meta?: any;
  severity_counts?: {
    high: number;
    medium: number;
    low: number;
  };
}

export interface DashboardResponse {
  status: string;
  analysis_data: Analysis | null;
  meta?: any;
  severity_counts?: {
    high: number;
    medium: number;
    low: number;
  };
  summary: DashboardSummary;
  recent_activities: any[];
}

export interface AnalysesResponse {
  status: string;
  count: number;
  analyses: Analysis[];
}

export interface SettingsPayload {
  emailNotifications: boolean;
  notificationEmail: string;
  smtpServer: string;
  smtpPort: number;
  smtpUser: string;
  smtpPassword?: string;
}

export interface Job {
  id: number;
  user_id: number;
  username: string;
  target_ip: string;
  log_path: string;
  frequency: string;
  status: string;
  created_at: string;
}

export interface JobApprovalResponse {
  status: string;
  message: string;
}

export interface Notification {
  id: number;
  title: string;
  message: string;
  type: 'info' | 'success' | 'warning' | 'error';
  is_read: boolean;
  created_at: string;
  link?: string;
}

export interface NotificationsResponse {
  status: string;
  notifications: Notification[];
}

@Injectable({
  providedIn: 'root'
})
export class LogService {
  private apiUrl = environment.apiUrl;
  private STORAGE_KEY = 'recent_ssh_connections';

  constructor(private http: HttpClient, private crypto: CryptoService) {}

  // ========== RECENT CONNECTIONS ==========
  /**
   * Sauvegarde une connexion dans la liste des 3 dernières connexions uniques.
   * Chiffre l'intégralité du tableau pour la sécurité.
   */
  saveConnection(conn: any): void {
    let currentHistory = this.getRecentConnections();
    
    // Règle : Distinct - Vérifier si l'hôte (IP) existe déjà
    // On retire l'ancienne entrée si elle existe pour qu'elle remonte en haut de la liste
    currentHistory = currentHistory.filter(h => h.host !== conn.host);
    
    // Règle : Stack Management - Ajouter au début (unshift)
    currentHistory.unshift(conn);
    
    // Règle : Limit - Garder seulement les 3 dernières
    const updatedHistory = currentHistory.slice(0, 3);
    
    // Sécurité : Chiffrer l'ensemble du tableau avant stockage
    const encryptedData = this.crypto.encryptObject(updatedHistory);
    localStorage.setItem(this.STORAGE_KEY, encryptedData);
  }

  /**
   * Récupère la liste des connexions récentes déchiffrée.
   */
  getRecentConnections(): any[] {
    const encryptedData = localStorage.getItem(this.STORAGE_KEY);
    if (!encryptedData) return [];
    
    try {
      const decrypted = this.crypto.decryptObject(encryptedData);
      return Array.isArray(decrypted) ? decrypted : [];
    } catch (e) {
      console.error('Erreur lors du déchiffrement de l\'historique SSH:', e);
      return [];
    }
  }

  // ========== ADMIN JOBS ==========
  getAdminJobs(): Observable<{ status: string; jobs: Job[] }> {
    return this.http.get<{ status: string; jobs: Job[] }>(`${this.apiUrl}/admin/jobs`);
  }

  approveAdminJob(jobId: number, action: 'approve' | 'refuse', reason?: string): Observable<JobApprovalResponse> {
    return this.http.post<JobApprovalResponse>(`${this.apiUrl}/admin/jobs/${jobId}/approve`, { action, reason });
  }

  // ========== NOTIFICATIONS ==========
  getNotifications(): Observable<NotificationsResponse> {
    return this.http.get<NotificationsResponse>(`${this.apiUrl}/notifications`);
  }

  markNotificationAsRead(notifId: number): Observable<{ status: string }> {
    return this.http.post<{ status: string }>(`${this.apiUrl}/notifications/${notifId}/read`, {});
  }

  // ========== DASHBOARD & ANALYSIS ==========
  getDashboard(): Observable<DashboardResponse> {
    return this.http.get<DashboardResponse>(`${this.apiUrl}/dashboard`);
  }

  getStats(period: string = '7d'): Observable<StatsResponse> {
    return this.http.get<StatsResponse>(`${this.apiUrl}/stats?period=${period}`);
  }

  getAnalyses(): Observable<AnalysesResponse> {
    return this.http.get<AnalysesResponse>(`${this.apiUrl}/analyses`);
  }

  getAnalysis(id: number): Observable<{ status: string; analysis: Analysis }> {
    return this.http.get<{ status: string; analysis: Analysis }>(`${this.apiUrl}/analyses/${id}`);
  }

  deleteAnalysis(id: number): Observable<{ status: string; message: string }> {
    return this.http.delete<{ status: string; message: string }>(`${this.apiUrl}/analyses/${id}`);
  }

  downloadAnalysisPdf(id: number): Observable<Blob> {
    return this.http.get(`${this.apiUrl}/analyses/${id}/pdf`, {
      responseType: 'blob'
    });
  }

  // ========== USER JOBS ==========
  createJob(payload: any): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/jobs`, payload);
  }

  getJobs(): Observable<{ status: string; jobs: any[] }> {
    return this.http.get<{ status: string; jobs: any[] }>(`${this.apiUrl}/jobs`);
  }

  getJob(id: number): Observable<{ status: string; job: any }> {
    return this.http.get<{ status: string; job: any }>(`${this.apiUrl}/jobs/${id}`);
  }

  deleteJob(id: number): Observable<{ status: string; message: string }> {
    return this.http.delete<{ status: string; message: string }>(`${this.apiUrl}/jobs/${id}`);
  }

  toggleJob(id: number): Observable<{ status: string; new_status: string; message: string }> {
    return this.http.post<{ status: string; new_status: string; message: string }>(`${this.apiUrl}/jobs/${id}/toggle`, {});
  }

  // ========== EMAIL & UPLOAD ==========
  sendReportEmail(payload: {
    analysis_id: number;
    recipient: string;
    sender_email?: string;
    app_password?: string;
    subject?: string;
    message?: string;
  }): Observable<{ success: boolean; message: string }> {
    return this.http.post<{ success: boolean; message: string }>(
      `${this.apiUrl}/email/send-report`,
      payload
    );
  }

  analyzeSshLog(payload: {
    host: string;
    user: string;
    pass: string;
    numLines: number | null;
  }): Observable<{ status: string; analysis_id?: number; message?: string }> {
    return this.http.post<{ status: string; analysis_id?: number; message?: string }>(`${this.apiUrl}/ssh/analyze`, payload);
  }

  uploadLogFile(file: File, numLines: number | null = null): Observable<any> {
    const formData = new FormData();
    formData.append('file', file);
    if (numLines !== null && numLines !== undefined) {
      formData.append('numLines', numLines.toString());
    }
    return this.http.post(`${this.apiUrl}/analyze-local`, formData, {
      reportProgress: true,
      observe: 'events'
    });
  }

  // ========== SETTINGS ==========
  getSettings(): Observable<{ status: string; settings: SettingsPayload }> {
    return this.http.get<{ status: string; settings: SettingsPayload }>(`${this.apiUrl}/settings`);
  }

  saveSettings(payload: SettingsPayload): Observable<{ status: string; message: string }> {
    return this.http.post<{ status: string; message: string }>(
      `${this.apiUrl}/settings`,
      payload
    );
  }
}
