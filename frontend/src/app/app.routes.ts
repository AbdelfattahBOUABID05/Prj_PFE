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
  { path: 'login', component: LoginComponent },
  { 
    path: '', 
    canActivate: [authGuard],
    children: [
      { path: 'dashboard', component: DashboardComponent },
      { path: 'ssh', component: SshComponent },
      { path: 'local-analysis', component: LocalAnalysisComponent },
      { path: 'history', component: LogHistoryComponent },
      { path: 'settings', component: SettingsComponent },
      { path: 'jobs', component: JobsComponent },
      { path: 'report', component: ReportComponent },
      { path: 'profile', loadComponent: () => import('./components/profile/profile.component').then(m => m.ProfileComponent) },
      
      // Admin Only Routes
      // Routes réservées aux administrateurs
      { 
        path: 'admin/users', 
        loadComponent: () => import('./components/admin/user-management/user-management.component').then(m => m.UserManagementComponent),
        data: { role: 'Admin' }
      },
      { 
        path: 'admin/jobs', 
        loadComponent: () => import('./components/admin/job-management/job-management.component').then(m => m.JobManagementComponent),
        data: { role: 'Admin' }
      },
      { 
        path: 'admin/console', 
        loadComponent: () => import('./components/admin/remote-console/remote-console.component').then(m => m.RemoteConsoleComponent),
        data: { role: 'Admin' }
      },
      
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' }
    ]
  },
  { path: '**', redirectTo: 'login' } 
];
