import { NavLink, useMatch } from "react-router-dom";
import {
  LayoutDashboard,
  ScanSearch,
  ShieldAlert,
  Clock,
  Settings,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useScanStore } from "../store/scanStore";

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Overview", end: true },
  { to: "/scan", icon: ScanSearch, label: "Scan", end: false },
  { to: "/quarantine", icon: ShieldAlert, label: "Quarantine", end: false },
  { to: "/history", icon: Clock, label: "History", end: false },
  { to: "/settings", icon: Settings, label: "Settings", end: false },
];

function SidebarNavItem({
  to,
  icon: Icon,
  label,
  end,
}: {
  to: string;
  icon: typeof LayoutDashboard;
  label: string;
  end: boolean;
}) {
  const match = useMatch({ path: to, end });
  return (
    <NavLink
      to={to}
      end={end}
      aria-current={match ? "page" : undefined}
      className={({ isActive }) =>
        cn(
          "flex items-center gap-2.5 rounded-md px-3 py-2 text-[13px] transition-colors",
          isActive
            ? "bg-white/[0.06] text-foreground"
            : "text-muted-foreground hover:bg-white/[0.03] hover:text-foreground"
        )
      }
    >
      <Icon className="h-4 w-4 opacity-70" strokeWidth={1.75} />
      <span>{label}</span>
    </NavLink>
  );
}

export default function Sidebar() {
  const { realtimeProtection } = useScanStore();

  return (
    <aside className="relative z-10 flex h-full w-[220px] shrink-0 flex-col border-r border-white/[0.06] bg-background/90 shadow-[inset_-1px_0_0_rgba(255,255,255,0.04)]">
      <div className="px-5 py-6">
        <div className="flex items-center gap-3">
          <img
            src="/brand/icon.png"
            alt=""
            className="h-9 w-9 shrink-0 rounded-md object-contain"
            width={36}
            height={36}
          />
          <div className="min-w-0">
            <p className="font-display text-[15px] font-medium tracking-tight text-foreground">
              Null Threat
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground">Local threat analysis</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 px-3">
        {navItems.map((item) => (
          <SidebarNavItem key={item.to} {...item} />
        ))}
      </nav>

      <div className="border-t border-border/80 px-5 py-4">
        <div className="flex items-center gap-2">
          <span
            className={cn(
              "h-1.5 w-1.5 rounded-full",
              realtimeProtection ? "bg-foreground" : "bg-muted-foreground"
            )}
          />
          <span className="text-xs text-muted-foreground">
            {realtimeProtection ? "Watching folders" : "Protection off"}
          </span>
        </div>
      </div>
    </aside>
  );
}
