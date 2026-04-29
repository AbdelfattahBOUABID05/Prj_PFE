import { Routes } from '@angular/router';
import { LoginComponent } from './components/login/login.component';
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { SshComponent } from './components/ssh-connection/ssh.component';
import { LocalAnalysisComponent } from './components/local-analysis/local-analysis.component';
import { LogHistoryComponent } from './components/log-history/log-history.component';
import { SettingsComponent } from './components/settings/settings.component';
import { JobsComponent } from './components/jobs/jobs.component';
import { ReportComponent } from './components/report/report.component';
import { authGuard } from './services/auth.guard';

// Lazy load admin components for better performance
// Chargement différé des composants admin pour de meilleures performances
export const routes: Routes = [
  { path: 'login', component: LoginComponent, data: { animation: 'LoginPage' } },
  { 
    path: '', 
    canActivate: [authGuard],
    children: [
      { path: 'dashboard', component: DashboardComponent, data: { animation: 'DashboardPage' } },
      { path: 'ssh', component: SshComponent, data: { animation: 'SshPage' } },
      { path: 'local-analysis', component: LocalAnalysisComponent, data: { animation: 'LocalPage' } },
      { path: 'history', component: LogHistoryComponent, data: { animation: 'HistoryPage' } },
      { path: 'settings', component: SettingsComponent, data: { animation: 'SettingsPage' } },
      { path: 'jobs', component: JobsComponent, data: { animation: 'JobsPage' } },
      { path: 'report', component: ReportComponent, data: { animation: 'ReportPage' } },
      { 
        path: 'profile', 
        loadComponent: () => import('./components/profile/profile.component').then(m => m.ProfileComponent),
        data: { animation: 'ProfilePage' } 
      },
      
      // Admin Only Routes
      // Routes réservées aux administrateurs
      { 
        path: 'admin/users', 
        loadComponent: () => import('./components/admin/user-management/user-management.component').then(m => m.UserManagementComponent),
        data: { role: 'Admin', animation: 'AdminUsersPage' }
      },
      { 
        path: 'admin/jobs', 
        loadComponent: () => import('./components/admin/job-management/job-management.component').then(m => m.JobManagementComponent),
        data: { role: 'Admin', animation: 'AdminJobsPage' }
      },
      { 
        path: 'admin/console', 
        loadComponent: () => import('./components/admin/remote-console/remote-console.component').then(m => m.RemoteConsoleComponent),
        data: { role: 'Admin', animation: 'AdminConsolePage' }
      },
      
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' }
    ]
  },
  { path: '**', redirectTo: 'login' } 
];
