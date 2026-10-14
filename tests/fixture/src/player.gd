extends Node2D

var speed := 120.0
var _velocity := Vector2.ZERO


func _ready() -> void:
	scale = Vector2.ONE
	_velocity = Vector2.ZERO


func move_player(direction: Vector2, delta: float) -> void:
	if direction.length() > 0.0:
		_velocity = direction.normalized() * speed
	else:
		_velocity = Vector2.ZERO
	for i in range(3):
		position += _velocity * delta * 0.5
	position += _velocity * delta
