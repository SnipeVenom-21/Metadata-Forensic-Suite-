import { Upload, Search, FileText, LogOut, User, Layers, Fingerprint, Wifi, Activity, LayoutDashboard, Globe2, ShieldAlert, BookOpen, Bot, BarChart3 } from 'lucide-react';
import { NavLink } from '@/components/NavLink';
import { useLocation } from 'react-router-dom';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/hooks/use-toast';
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarHeader,
  SidebarFooter,
  useSidebar,
} from '@/components/ui/sidebar';
import { Button } from '@/components/ui/button';

const navItems = [
  { title: 'Dashboard', url: '/', icon: LayoutDashboard },
  { title: 'Upload', url: '/upload', icon: Upload },
  { title: 'Analysis', url: '/analysis', icon: Search },
  { title: 'Risk Score', url: '/risk-score', icon: BarChart3 },
  { title: 'Reports', url: '/reports', icon: FileText },
  { title: 'Normalize', url: '/normalize', icon: Layers },
  { title: 'Attribution', url: '/attribution', icon: Fingerprint },
  { title: 'Network Origin', url: '/network-origin', icon: Wifi },
  { title: 'Lifecycle', url: '/lifecycle', icon: Activity },
  { title: 'Geo & Device', url: '/geo-device', icon: Globe2 },
  { title: 'Privacy Risk', url: '/privacy-risk', icon: ShieldAlert },
  { title: 'Forensic Report', url: '/forensic-report', icon: BookOpen },
  { title: 'AI Analyst', url: '/ai-analyst', icon: Bot },
];

export function AppSidebar() {
  const { state } = useSidebar();
  const collapsed = state === 'collapsed';
  const location = useLocation();
  const { user, logout } = useAuth();
  const { toast } = useToast();

  const handleLogout = async () => {
    try {
      await logout();
      toast({ title: 'Signed out', description: 'You have been signed out.' });
    } catch {
      toast({ title: 'Error', description: 'Failed to sign out.', variant: 'destructive' });
    }
  };

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader className="p-4 border-b border-border">
        <div className="flex items-center gap-3">
          <LayoutDashboard className="h-7 w-7 text-primary shrink-0" />
          {!collapsed && (
            <div>
              <h1 className="text-sm font-bold text-foreground tracking-tight leading-tight">Metadata Forensic</h1>
              <p className="text-[10px] text-muted-foreground font-mono tracking-widest uppercase">Suite</p>
            </div>
          )}
        </div>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel className="text-[10px] tracking-widest uppercase text-muted-foreground">Navigation</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton asChild>
                    <NavLink
                      to={item.url}
                      end
                      className="hover:bg-accent/50 transition-colors"
                      activeClassName="bg-primary/10 text-primary font-medium border-l-2 border-primary"
                    >
                      <item.icon className="mr-2 h-4 w-4" />
                      {!collapsed && <span>{item.title}</span>}
                    </NavLink>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      {/* User info + logout in sidebar footer */}
      <SidebarFooter className="p-3 border-t border-border">
        {user && (
          <div className={`flex ${collapsed ? 'flex-col items-center gap-2' : 'items-center gap-2'}`}>
            {/* Avatar */}
            {user.photoURL ? (
              <img
                src={user.photoURL}
                alt="avatar"
                className="h-7 w-7 rounded-full shrink-0 border border-border"
              />
            ) : (
              <div className="h-7 w-7 rounded-full bg-primary/20 border border-primary/30 flex items-center justify-center shrink-0">
                <User className="h-4 w-4 text-primary" />
              </div>
            )}

            {!collapsed && (
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-foreground truncate">
                  {user.displayName || user.email?.split('@')[0]}
                </p>
                <p className="text-[10px] text-muted-foreground truncate">{user.email}</p>
              </div>
            )}

            <Button
              id="logout-btn"
              size="icon"
              variant="ghost"
              className="h-7 w-7 shrink-0 text-muted-foreground hover:text-foreground"
              onClick={handleLogout}
              title="Sign out"
            >
              <LogOut className="h-3.5 w-3.5" />
            </Button>
          </div>
        )}
      </SidebarFooter>
    </Sidebar>
  );
}
