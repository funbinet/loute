import 'package:flutter/material.dart';

/// Represents an input field definition for an action.
class InputField {
  final String key;
  final String label;
  final String hint;
  final InputFieldType type;
  final dynamic defaultValue;
  final bool required;

  const InputField({
    required this.key,
    required this.label,
    this.hint = '',
    this.type = InputFieldType.text,
    this.defaultValue,
    this.required = true,
  });
}

enum InputFieldType { text, number, filePath, dropdown, toggle }

/// A single executable action within a module.
class ActionItem {
  final String id;
  final String moduleId;
  final String name;
  final String rustFunction;
  final String executionStyle;
  final List<InputField> inputs;
  final String outputType; // html, table, badge, log
  final List<String>? supportedPlatforms; // null means all platforms are supported
  final IconData icon;
  final String description;

  const ActionItem({
    required this.id,
    required this.moduleId,
    required this.name,
    required this.icon,
    required this.rustFunction,
    this.executionStyle = 'async',
    this.inputs = const [],
    this.outputType = 'html',
    this.supportedPlatforms,
    this.description = 'Executes the core function to analyze targets and identify vulnerabilities.',
  });
}

/// A module groups related actions within a phase.
class Module {
  final String id;
  final String phaseId;
  final String name;
  final String description;
  final IconData icon;
  final List<ActionItem> actions;

  const Module({
    required this.id,
    required this.phaseId,
    required this.name,
    required this.icon,
    this.description = '',
    this.actions = const [],
  });
}

/// A phase is the top-level grouping (10 phases total).
class Phase {
  final String id;
  final String name;
  final String description;
  final IconData icon;
  final List<Module> modules;

  const Phase({
    required this.id,
    required this.name,
    required this.icon,
    this.description = '',
    this.modules = const [],
  });
}
