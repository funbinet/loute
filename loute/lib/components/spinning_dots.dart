import 'package:flutter/material.dart';

class SpinningDotsIndicator extends StatefulWidget {
  final Color color;
  final double fontSize;

  const SpinningDotsIndicator({
    super.key,
    required this.color,
    this.fontSize = 14,
  });

  @override
  State<SpinningDotsIndicator> createState() => _SpinningDotsIndicatorState();
}

class _SpinningDotsIndicatorState extends State<SpinningDotsIndicator> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  // Standard terminal spinner characters
  final List<String> _frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

  @override
  void initState() {
    super.initState();
    // 80ms per frame * 10 frames = 800ms
    _controller = AnimationController(vsync: this, duration: const Duration(milliseconds: 800))..repeat();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _controller,
      builder: (context, child) {
        final frameIndex = (_controller.value * _frames.length).floor() % _frames.length;
        return Text(
          _frames[frameIndex],
          style: TextStyle(
            fontFamily: 'monospace',
            fontWeight: FontWeight.bold,
            fontSize: widget.fontSize,
            color: widget.color,
          ),
        );
      },
    );
  }
}
