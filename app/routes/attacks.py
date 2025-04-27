from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import AttackGroup, User
from app import db

attacks_bp = Blueprint("attacks", __name__)


def attack_to_dict(attack):
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

@attacks_bp.route("/attacks/ongoing", methods=["GET"])
@jwt_required()
def list_ongoing_attacks():
    """
    Return all AttackGroups where is_resolved == False.
    """
    try:
        current_user_id = int(get_jwt_identity())
        if not User.query.get(current_user_id):
            return jsonify({"error": "User not found"}), 404

        limit = request.args.get("limit", default=None, type=int)
        if limit is not None and limit <= 0:
            return jsonify({"error": "limit must be a positive integer"}), 400

        query = (
            AttackGroup.query
            .filter_by(is_resolved=False)
            .order_by(AttackGroup.id.desc())
        )
        if limit:
            query = query.limit(limit)

        groups = query.all()
        data = [attack_to_dict(g) for g in groups]

        return jsonify({"count": len(data), "attacks": data}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500