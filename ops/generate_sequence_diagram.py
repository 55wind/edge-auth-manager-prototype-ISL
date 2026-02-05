#!/usr/bin/env python3
"""
Generate sequence diagram for the full auth flow.
Boot → Register → Approve → Auth → Authorization → Data Exchange
"""
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"

# Set Korean font
plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False


def draw_sequence_diagram():
    fig, ax = plt.subplots(1, 1, figsize=(14, 10))
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 12)
    ax.axis('off')

    # Colors
    AGENT_COLOR = '#4CAF50'      # Green
    MANAGER_COLOR = '#2196F3'    # Blue
    RABBITMQ_COLOR = '#FF9800'   # Orange
    ADMIN_COLOR = '#9C27B0'      # Purple
    ARROW_COLOR = '#333333'

    # Lifeline positions
    agent_x = 2
    manager_x = 7
    rabbitmq_x = 12
    admin_x = 4.5

    # Title
    ax.text(7, 11.5, '인증·데이터 흐름 시퀀스', fontsize=22, fontweight='bold', ha='center')
    ax.text(7, 11.0, 'Boot → Register → Approve → Auth → Authorization → Data Exchange',
            fontsize=14, ha='center', color='#666666')

    # Draw actors (boxes at top)
    actor_y = 10.2
    box_width = 1.8
    box_height = 0.6

    # Agent box
    agent_box = mpatches.FancyBboxPatch((agent_x - box_width/2, actor_y), box_width, box_height,
                                         boxstyle="round,pad=0.05", facecolor=AGENT_COLOR,
                                         edgecolor='black', linewidth=2)
    ax.add_patch(agent_box)
    ax.text(agent_x, actor_y + box_height/2, 'Agent', ha='center', va='center',
            fontweight='bold', color='white', fontsize=14)

    # Manager box
    manager_box = mpatches.FancyBboxPatch((manager_x - box_width/2, actor_y), box_width, box_height,
                                           boxstyle="round,pad=0.05", facecolor=MANAGER_COLOR,
                                           edgecolor='black', linewidth=2)
    ax.add_patch(manager_box)
    ax.text(manager_x, actor_y + box_height/2, 'Manager', ha='center', va='center',
            fontweight='bold', color='white', fontsize=14)

    # RabbitMQ box
    rmq_box = mpatches.FancyBboxPatch((rabbitmq_x - box_width/2, actor_y), box_width, box_height,
                                       boxstyle="round,pad=0.05", facecolor=RABBITMQ_COLOR,
                                       edgecolor='black', linewidth=2)
    ax.add_patch(rmq_box)
    ax.text(rabbitmq_x, actor_y + box_height/2, 'RabbitMQ', ha='center', va='center',
            fontweight='bold', color='white', fontsize=14)

    # Draw lifelines (dashed vertical lines)
    lifeline_top = actor_y
    lifeline_bottom = 0.5
    ax.plot([agent_x, agent_x], [lifeline_top, lifeline_bottom], 'k--', linewidth=1, alpha=0.5)
    ax.plot([manager_x, manager_x], [lifeline_top, lifeline_bottom], 'k--', linewidth=1, alpha=0.5)
    ax.plot([rabbitmq_x, rabbitmq_x], [lifeline_top, lifeline_bottom], 'k--', linewidth=1, alpha=0.5)

    # Helper function for arrows
    def draw_arrow(x1, x2, y, label, color=ARROW_COLOR, response=False):
        if response:
            # Response: arrow from x1 to x2 (dashed)
            ax.annotate('', xy=(x2, y), xytext=(x1, y),
                       arrowprops=dict(arrowstyle='->', color=color, lw=2, ls='--'))
        else:
            # Request: arrow from x1 to x2 (solid)
            ax.annotate('', xy=(x2, y), xytext=(x1, y),
                       arrowprops=dict(arrowstyle='->', color=color, lw=2.5))

        mid_x = (x1 + x2) / 2
        offset = 0.15
        ax.text(mid_x, y + offset, label, ha='center', va='bottom', fontsize=12,
                color=color if response else 'black')

    # Helper for phase labels
    def draw_phase(y, label, color):
        ax.text(0.3, y, label, ha='left', va='center', fontsize=13, fontweight='bold',
                color=color, bbox=dict(boxstyle='round,pad=0.3', facecolor=color, alpha=0.2))

    # === PHASE 1: Boot ===
    y = 9.3
    draw_phase(y, '1. Boot', AGENT_COLOR)
    ax.text(agent_x + 0.1, y, 'mTLS 인증서 로드', ha='left', va='center', fontsize=11,
            style='italic', color='#666666')

    # === PHASE 2: Register ===
    y = 8.4
    draw_phase(y, '2. Register', AGENT_COLOR)
    draw_arrow(agent_x, manager_x, y, 'POST /device/register')

    y = 7.8
    draw_arrow(manager_x, agent_x, y, 'status: PENDING', response=True)

    # === PHASE 3: Approve (Admin action) ===
    y = 7.0
    draw_phase(y, '3. Approve', ADMIN_COLOR)
    # Admin appears temporarily
    ax.text(admin_x, y, '[Admin]', ha='center', va='center', fontsize=12,
            fontweight='bold', color=ADMIN_COLOR)
    ax.annotate('', xy=(manager_x, y - 0.1), xytext=(admin_x + 0.5, y - 0.1),
               arrowprops=dict(arrowstyle='->', color=ADMIN_COLOR, lw=2.5))
    ax.text((admin_x + manager_x) / 2 + 0.3, y + 0.15, 'POST /device/approve',
            ha='center', fontsize=12)

    y = 6.4
    draw_arrow(manager_x, agent_x, y, 'status: APPROVED', response=True, color=ADMIN_COLOR)

    # === PHASE 4: Auth (Token) ===
    y = 5.6
    draw_phase(y, '4. Auth', MANAGER_COLOR)
    draw_arrow(agent_x, manager_x, y, 'POST /auth/token')

    y = 5.0
    draw_arrow(manager_x, agent_x, y, 'JWT access_token (TTL: 900s)', response=True)

    # === PHASE 5: Authorization ===
    y = 4.2
    draw_phase(y, '5. Authorization', MANAGER_COLOR)
    draw_arrow(agent_x, manager_x, y, 'API + Bearer Token')

    y = 3.6
    draw_arrow(manager_x, agent_x, y, 'RBAC OK -> 200', response=True)

    # === PHASE 6: Data Exchange ===
    y = 2.8
    draw_phase(y, '6. Data Exchange', RABBITMQ_COLOR)
    draw_arrow(agent_x, rabbitmq_x, y, 'AMQP Publish (TLS 5671)')
    ax.text((agent_x + rabbitmq_x) / 2, y - 0.35, 'queue: agent.metadata',
            ha='center', fontsize=11, color='#666666', style='italic')

    # Token refresh note
    y = 1.8
    ax.text(agent_x - 0.3, y, '*', fontsize=16, ha='center', va='center', color=MANAGER_COLOR)
    ax.text(agent_x + 0.1, y, '80% TTL (12min) 자동 갱신', ha='left', va='center',
            fontsize=11, color='#666666', style='italic')

    # Buffer note
    y = 1.2
    ax.text(agent_x - 0.3, y, '*', fontsize=16, ha='center', va='center', color=RABBITMQ_COLOR)
    ax.text(agent_x + 0.1, y, '연결 단절 시 로컬 버퍼 저장', ha='left', va='center',
            fontsize=11, color='#666666', style='italic')

    # Legend
    legend_y = 0.3
    ax.text(7, legend_y, '-> 요청  - - -> 응답', ha='center', fontsize=11, color='#888888')

    plt.tight_layout()

    # Save
    output_path = SCREENSHOTS_DIR / "61_auth_flow_sequence.png"
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white', edgecolor='none')
    plt.close()

    print(f"Saved: {output_path}")
    return output_path


if __name__ == "__main__":
    print("Generating Auth Flow Sequence Diagram...")
    draw_sequence_diagram()
    print("Done!")
