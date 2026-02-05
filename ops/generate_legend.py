#!/usr/bin/env python3
"""
Generate legend diagram explaining the arrows and colors in the sequence diagram.
"""
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"

# Set Korean font
plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False


def draw_legend():
    fig, ax = plt.subplots(1, 1, figsize=(12, 8))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 10)
    ax.axis('off')

    # Colors
    AGENT_COLOR = '#4CAF50'      # Green
    MANAGER_COLOR = '#2196F3'    # Blue
    RABBITMQ_COLOR = '#FF9800'   # Orange
    ADMIN_COLOR = '#9C27B0'      # Purple
    ARROW_COLOR = '#333333'

    # Title
    ax.text(6, 9.5, '시퀀스 다이어그램 범례', fontsize=20, fontweight='bold', ha='center')

    # === Section 1: Arrow Types ===
    ax.text(1, 8.5, '화살표 유형', fontsize=16, fontweight='bold', color='#333333')

    # Request arrow (solid)
    y = 7.6
    ax.annotate('', xy=(5, y), xytext=(2, y),
               arrowprops=dict(arrowstyle='->', color=ARROW_COLOR, lw=2.5))
    ax.text(6, y, '요청 (Request)', fontsize=14, va='center')
    ax.text(6, y - 0.4, 'Agent → Manager / Manager → RabbitMQ', fontsize=11, va='center', color='#666666')

    # Response arrow (dashed)
    y = 6.4
    ax.annotate('', xy=(2, y), xytext=(5, y),
               arrowprops=dict(arrowstyle='->', color=ARROW_COLOR, lw=2, ls='--'))
    ax.text(6, y, '응답 (Response)', fontsize=14, va='center')
    ax.text(6, y - 0.4, 'Manager → Agent (상태/토큰 반환)', fontsize=11, va='center', color='#666666')

    # Admin arrow (purple)
    y = 5.2
    ax.annotate('', xy=(5, y), xytext=(2, y),
               arrowprops=dict(arrowstyle='->', color=ADMIN_COLOR, lw=2.5))
    ax.text(6, y, '관리자 액션 (Admin Action)', fontsize=14, va='center')
    ax.text(6, y - 0.4, 'Dashboard에서 수동 승인/폐기', fontsize=11, va='center', color='#666666')

    # === Section 2: Component Colors ===
    ax.text(1, 4.0, '컴포넌트 색상', fontsize=16, fontweight='bold', color='#333333')

    # Agent (Green)
    y = 3.2
    box = mpatches.FancyBboxPatch((1.5, y - 0.25), 1.5, 0.5,
                                   boxstyle="round,pad=0.05", facecolor=AGENT_COLOR,
                                   edgecolor='black', linewidth=2)
    ax.add_patch(box)
    ax.text(2.25, y, 'Agent', ha='center', va='center', fontweight='bold', color='white', fontsize=12)
    ax.text(4, y, '엣지 디바이스 보안 모듈', fontsize=13, va='center')

    # Manager (Blue)
    y = 2.4
    box = mpatches.FancyBboxPatch((1.5, y - 0.25), 1.5, 0.5,
                                   boxstyle="round,pad=0.05", facecolor=MANAGER_COLOR,
                                   edgecolor='black', linewidth=2)
    ax.add_patch(box)
    ax.text(2.25, y, 'Manager', ha='center', va='center', fontweight='bold', color='white', fontsize=12)
    ax.text(4, y, '인증/인가 API 서버', fontsize=13, va='center')

    # RabbitMQ (Orange)
    y = 1.6
    box = mpatches.FancyBboxPatch((1.5, y - 0.25), 1.5, 0.5,
                                   boxstyle="round,pad=0.05", facecolor=RABBITMQ_COLOR,
                                   edgecolor='black', linewidth=2)
    ax.add_patch(box)
    ax.text(2.25, y, 'RabbitMQ', ha='center', va='center', fontweight='bold', color='white', fontsize=12)
    ax.text(4, y, '메시지 브로커 (Gateway)', fontsize=13, va='center')

    # Admin (Purple)
    y = 0.8
    ax.text(2.25, y, '[Admin]', ha='center', va='center', fontweight='bold', color=ADMIN_COLOR, fontsize=12)
    ax.text(4, y, '시스템 관리자 (Dashboard 사용)', fontsize=13, va='center')

    plt.tight_layout()

    # Save
    output_path = SCREENSHOTS_DIR / "62_sequence_legend.png"
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white', edgecolor='none')
    plt.close()

    print(f"Saved: {output_path}")
    return output_path


if __name__ == "__main__":
    print("Generating Sequence Diagram Legend...")
    draw_legend()
    print("Done!")
