#!/usr/bin/env python3
"""
Generate exception handling flow diagram.
1. Token Expiration (만료)
2. Duplicate Registration (중복등록)
3. Connection Drop (단절)
"""
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from pathlib import Path

SCREENSHOTS_DIR = Path(__file__).parent.parent / "docs" / "screenshots"

# Set Korean font
plt.rcParams['font.family'] = 'Malgun Gothic'
plt.rcParams['axes.unicode_minus'] = False


def draw_exception_flows():
    fig, axes = plt.subplots(1, 3, figsize=(18, 10))

    # Colors
    AGENT_COLOR = '#4CAF50'
    MANAGER_COLOR = '#2196F3'
    RABBITMQ_COLOR = '#FF9800'
    ERROR_COLOR = '#F44336'
    SUCCESS_COLOR = '#4CAF50'
    BUFFER_COLOR = '#9E9E9E'

    # ============================================================
    # 1. Token Expiration Flow (만료)
    # ============================================================
    ax = axes[0]
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 12)
    ax.axis('off')

    ax.text(5, 11.5, '1. 토큰 만료 처리', fontsize=16, fontweight='bold', ha='center')
    ax.text(5, 10.8, 'Token Expiration', fontsize=12, ha='center', color='#666666')

    # Flow boxes
    def draw_box(ax, x, y, text, color, width=3, height=0.8):
        box = mpatches.FancyBboxPatch((x - width/2, y - height/2), width, height,
                                       boxstyle="round,pad=0.05", facecolor=color,
                                       edgecolor='black', linewidth=1.5)
        ax.add_patch(box)
        ax.text(x, y, text, ha='center', va='center', fontsize=10,
                fontweight='bold', color='white' if color != '#FFFFFF' else 'black')

    def draw_arrow_down(ax, x, y1, y2, label='', color='#333333'):
        ax.annotate('', xy=(x, y2), xytext=(x, y1),
                   arrowprops=dict(arrowstyle='->', color=color, lw=2))
        if label:
            ax.text(x + 0.2, (y1 + y2) / 2, label, fontsize=9, va='center', color='#666666')

    # Token Expiration Flow
    y = 9.5
    draw_box(ax, 5, y, 'JWT 토큰 발급', MANAGER_COLOR)
    ax.text(7.5, y, 'TTL: 900초', fontsize=9, va='center', color='#666666')

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2)
    y = 8.0
    draw_box(ax, 5, y, '시간 경과 체크', AGENT_COLOR)

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2, '80% (720초) 도달')
    y = 6.5
    draw_box(ax, 5, y, '자동 갱신 트리거', AGENT_COLOR)

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2)
    y = 5.0
    draw_box(ax, 5, y, 'POST /auth/token', MANAGER_COLOR)

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2)
    y = 3.5
    draw_box(ax, 5, y, '새 토큰 발급', SUCCESS_COLOR)

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2)
    y = 2.0
    draw_box(ax, 5, y, '서비스 무중단', SUCCESS_COLOR)

    # Code reference
    ax.text(5, 0.8, 'services/agent/agent/run.py:87', fontsize=9, ha='center',
            color='#999999', style='italic')

    # ============================================================
    # 2. Duplicate Registration Flow (중복등록)
    # ============================================================
    ax = axes[1]
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 12)
    ax.axis('off')

    ax.text(5, 11.5, '2. 중복 등록 처리', fontsize=16, fontweight='bold', ha='center')
    ax.text(5, 10.8, 'Duplicate Registration', fontsize=12, ha='center', color='#666666')

    # Duplicate Registration Flow
    y = 9.5
    draw_box(ax, 5, y, 'POST /device/register', AGENT_COLOR)
    ax.text(7.8, y, '기존 디바이스', fontsize=9, va='center', color='#666666')

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2)
    y = 8.0
    draw_box(ax, 5, y, 'namespace 확인', MANAGER_COLOR)

    # Branch
    ax.annotate('', xy=(3, y - 1.5), xytext=(5, y - 0.5),
               arrowprops=dict(arrowstyle='->', color='#333333', lw=2))
    ax.annotate('', xy=(7, y - 1.5), xytext=(5, y - 0.5),
               arrowprops=dict(arrowstyle='->', color='#333333', lw=2))

    ax.text(3.5, 7.2, '같은 fingerprint', fontsize=9, color='#666666')
    ax.text(6, 7.2, '다른 fingerprint', fontsize=9, color='#666666')

    # Left branch (same fingerprint - OK)
    y = 6.2
    draw_box(ax, 3, y, '멱등성 처리', SUCCESS_COLOR)
    draw_arrow_down(ax, 3, y - 0.5, y - 1.2)
    y = 4.7
    draw_box(ax, 3, y, '200 OK', SUCCESS_COLOR)
    ax.text(3, 4.0, '기존 상태 유지', fontsize=9, ha='center', color='#666666')

    # Right branch (different fingerprint - Error)
    y = 6.2
    draw_box(ax, 7, y, 'fingerprint 불일치', ERROR_COLOR)
    draw_arrow_down(ax, 7, y - 0.5, y - 1.2)
    y = 4.7
    draw_box(ax, 7, y, '409 Conflict', ERROR_COLOR)
    ax.text(7, 4.0, '등록 거부', fontsize=9, ha='center', color='#666666')

    # Security incident
    draw_arrow_down(ax, 7, 4.3, 3.2)
    y = 2.8
    draw_box(ax, 7, y, 'DUPLICATE_FINGERPRINT', ERROR_COLOR, width=3.5)
    ax.text(7, 2.1, '보안 인시던트 기록', fontsize=9, ha='center', color='#666666')

    # Code reference
    ax.text(5, 0.8, 'services/manager/manager/main.py:217', fontsize=9, ha='center',
            color='#999999', style='italic')

    # ============================================================
    # 3. Connection Drop Flow (단절)
    # ============================================================
    ax = axes[2]
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 12)
    ax.axis('off')

    ax.text(5, 11.5, '3. 연결 단절 처리', fontsize=16, fontweight='bold', ha='center')
    ax.text(5, 10.8, 'Connection Drop', fontsize=12, ha='center', color='#666666')

    # Connection Drop Flow
    y = 9.5
    draw_box(ax, 5, y, 'AMQP 연결 끊김', ERROR_COLOR)
    ax.text(7.8, y, '네트워크/키 로테이션', fontsize=9, va='center', color='#666666')

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2)
    y = 8.0
    draw_box(ax, 5, y, '로컬 버퍼 저장', BUFFER_COLOR)
    ax.text(7.5, y, 'unsent.jsonl', fontsize=9, va='center', color='#666666')

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2)
    y = 6.5
    draw_box(ax, 5, y, '재연결 시도', AGENT_COLOR)
    ax.text(7.8, y, '최대 30회', fontsize=9, va='center', color='#666666')

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2, 'Exponential Backoff')
    y = 5.0
    draw_box(ax, 5, y, '0.5s ~ 20s 대기', AGENT_COLOR)

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2)
    y = 3.5
    draw_box(ax, 5, y, '재연결 성공', SUCCESS_COLOR)

    draw_arrow_down(ax, 5, y - 0.5, y - 1.2)
    y = 2.0
    draw_box(ax, 5, y, '버퍼 Flush (200개)', SUCCESS_COLOR)
    ax.text(5, 1.3, '데이터 무손실', fontsize=10, ha='center', color=SUCCESS_COLOR, fontweight='bold')

    # Code reference
    ax.text(5, 0.5, 'services/agent/agent/amqp_pub.py:47-93', fontsize=9, ha='center',
            color='#999999', style='italic')

    plt.tight_layout()

    # Save
    output_path = SCREENSHOTS_DIR / "63_exception_flows.png"
    plt.savefig(output_path, dpi=150, bbox_inches='tight', facecolor='white', edgecolor='none')
    plt.close()

    print(f"Saved: {output_path}")
    return output_path


if __name__ == "__main__":
    print("Generating Exception Flow Diagram...")
    draw_exception_flows()
    print("Done!")
