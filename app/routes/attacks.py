from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import AttackGroup, User
from app import db

attacks_bp = Blueprint("attacks", __name__)


def attack_to_dict(attack):
    """Lightweight serializer (adjust as you add columns)."""
    return {
        "id":          attack.id,
        "attack_id":   attack.attack_id,
        "attack_type": attack.attack_type,
        "start_time":  attack.start_time,
        "is_resolved": attack.is_resolved,
    }


@attacks_bp.route("/attacks/<int:attack_id>/resolve", methods=["PATCH"])
@jwt_required()
def resolve_attack_group(attack_id: int):
    """
    Mark an AttackGroup (by attack_id) as resolved.
    Expects no body. Returns the updated row.

    Example:
        PATCH /api/attacks/7/resolve      ← sets is_resolved = true
    """
    try:
        current_user_id = int(get_jwt_identity())
        if not User.query.get(current_user_id):
            return jsonify({"error": "User not found"}), 404

        group = AttackGroup.query.filter_by(attack_id=attack_id).first()
        if not group:
            return jsonify({"error": f"AttackGroup {attack_id} not found"}), 404

        if group.is_resolved:
            return (
                jsonify(
                    {
                        "message": "AttackGroup already resolved",
                        "attack": attack_to_dict(group),
                    }
                ),
                200,
            )

        group.is_resolved = True
        db.session.commit()

        return jsonify({"message": "AttackGroup resolved", "attack": attack_to_dict(group)}), 200


    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
