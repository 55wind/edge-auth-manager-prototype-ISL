#!/usr/bin/env python3
"""
Generate autoscale architecture diagram.
Stateless Manager + Load Balancer + External DB
"""
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"

# Set Korean font
plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False


def draw_autoscale_diagram():
    fig, ax = plt.subplots(1, 1, figsize=(12, 9))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 11)
    ax.axis('off')

    # Colors
    LB_COLOR = '#9C27B0'       # Purple - Load Balancer
    MANAGER_COLOR = '#2196F3'  # Blue - Manager
    DB_COLOR = '#FF9800'       # Orange - Database
    AGENT_COLOR = '#4CAF50'    # Green - Agent
    HEALTH_COLOR = '#4CAF50'   # Green - Health check
    ARROW_COLOR = '#333333'

    # Title
    ax.text(6, 10.5, 'Stateless 오토스케일 아키텍처', fontsize=22, fontweight='bold', ha='center')
    ax.text(6, 9.9, 'Horizontal Scaling with Load Balancer & External Database',
            fontsize=13, ha='center', color='#666666')

    # Helper function for boxes
    def draw_box(x, y, width, height, text, color, fontsize=12, subtext=None):
        box = mpatches.FancyBboxPatch((x - width/2, y - height/2), width, height,
                                       boxstyle="round,pad=0.05", facecolor=color,
                                       edgecolor='black', linewidth=2)
        ax.add_patch(box)
        if subtext:
            ax.text(x, y + 0.15, text, ha='center', va='center', fontsize=fontsize,
                    fontweight='bold', color='white')
            ax.text(x, y - 0.25, subtext, ha='center', va='center', fontsize=10,
                    color='white', alpha=0.9)
        elif text:
            ax.text(x, y, text, ha='center', va='center', fontsize=fontsize,
                    fontweight='bold', color='white')

    # Helper for dashed box (stateless indicator)
    def draw_dashed_box(x, y, width, height, label):
        rect = mpatches.FancyBboxPatch((x - width/2, y - height/2), width, height,
                                        boxstyle="round,pad=0.1", facecolor='none',
                                        edgecolor='#999999', linewidth=2, linestyle='--')
        ax.add_patch(rect)
        ax.text(x, y + height/2 + 0.25, label, ha='center', va='bottom', fontsize=11,
                color='#666666', style='italic')

    # =====================================================
    # 1. Agents (Top Left) - Only first one has text
    # =====================================================
    agent_y = 8.5
    ax.text(1.8, agent_y + 1.0, 'Edge Devices', fontsize=12, ha='center',
            fontweight='bold', color=AGENT_COLOR)

    # Draw stacked agents - only front one has text
    for i, offset in enumerate([0.6, 0.3, 0]):
        text = 'Agent' if i == 2 else ''  # Only the front box has text
        draw_box(1.8 + offset * 0.3, agent_y - offset, 1.2, 0.6, text, AGENT_COLOR, fontsize=11)

    # =====================================================
    # 2. Load Balancer
    # =====================================================
    lb_y = 8.5
    draw_box(6, lb_y, 3.5, 1.0, 'Load Balancer', LB_COLOR, fontsize=14, subtext='(nginx / AWS ALB)')

    # Arrow from Agents to LB
    ax.annotate('', xy=(4, lb_y), xytext=(2.8, lb_y),
               arrowprops=dict(arrowstyle='->', color=ARROW_COLOR, lw=2.5))
    ax.text(3.4, lb_y + 0.3, 'HTTPS', fontsize=10, ha='center', color='#666666')

    # =====================================================
    # 3. Manager Instances (Stateless)
    # =====================================================
    manager_y = 5.5

    # Dashed box around managers (Stateless zone)
    draw_dashed_box(6, manager_y, 9, 2.2, 'Stateless Zone (수평 확장 가능)')

    # Manager boxes
    manager_positions = [3, 6, 9]
    for i, mx in enumerate(manager_positions):
        label = f'Manager {i+1}' if i < 2 else 'Manager N'
        draw_box(mx, manager_y, 2.2, 1.2, label, MANAGER_COLOR, fontsize=12,
                 subtext='/healthz OK')

    # Arrows from LB to Managers
    for mx in manager_positions:
        ax.annotate('', xy=(mx, manager_y + 0.7), xytext=(6, lb_y - 0.6),
                   arrowprops=dict(arrowstyle='->', color=ARROW_COLOR, lw=2))

    # Health check annotation
    ax.text(10.5, 7.2, '/healthz 헬스체크', fontsize=11, ha='left', color=HEALTH_COLOR,
            fontweight='bold')
    ax.annotate('', xy=(9, manager_y + 0.7), xytext=(10.5, 7.0),
               arrowprops=dict(arrowstyle='->', color=HEALTH_COLOR, lw=1.5, ls='--'))

    # =====================================================
    # 4. External Database
    # =====================================================
    db_y = 2.5

    # Draw database box
    draw_box(6, db_y, 4, 1.2, 'External Database', DB_COLOR, fontsize=14,
             subtext='PostgreSQL / SQLite')

    # Arrows from Managers to DB
    for mx in manager_positions:
        ax.annotate('', xy=(6 + (mx - 6) * 0.3, db_y + 0.7), xytext=(mx, manager_y - 0.7),
                   arrowprops=dict(arrowstyle='<->', color=ARROW_COLOR, lw=2))

    # =====================================================
    # 5. Autoscale Explanation (in diagram)
    # =====================================================
    explain_y = 1.0
    ax.text(6, explain_y, '오토스케일 = 트래픽 증가 시 Manager 복제본 자동 추가, 감소 시 자동 제거',
            fontsize=12, ha='center', color='#333333', fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='#E3F2FD', edgecolor='#2196F3', linewidth=1.5))

    # =====================================================
    # 6. Legend note
    # =====================================================
    ax.text(6, 0.3, '* Stateless: 각 Manager는 로컬 상태 없이 동일하게 동작 (JWT 토큰 + 외부 DB)',
            fontsize=10, ha='center', color='#888888', style='italic')

    plt.tight_layout()

    # Save
    output_path = SCREENSHOTS_DIR / "67_autoscale_architecture.png"
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white', edgecolor='none')
    plt.close()

    print(f"Saved: {output_path}")
    return output_path


if __name__ == "__main__":
    print("Generating Autoscale Architecture Diagram...")
    draw_autoscale_diagram()
    print("Done!")
