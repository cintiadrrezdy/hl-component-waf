CloudFormation do

  if defined?(type) and type.downcase == 'regional'
    type = 'Regional'
  else
    type = ''
  end

  export_rules = true if !defined?(export_rules)
  export_acl = true if !defined?(export_acl)

  Condition("AssociateWithResource", FnNot(FnEquals(Ref('AssociatedResourceArn'), '')))
  Condition('IsUseWAFv1', FnNot(FnEquals(Ref('EnvironmentName'), 'NOTHING')))

  Description "#{component_name} - #{component_version}"

  safe_stack_name = FnJoin('', FnSplit('-', Ref('AWS::StackName')))

  # SQL injection match conditions
  sql_injection_match_sets.each do |name, sets|
    tuple_list = []

    sets.each do |tuple|
      object = {}
      object[:FieldToMatch] = {}
      object[:FieldToMatch][:Type] = tuple["field_type"]
      object[:FieldToMatch][:Data] = tuple["field_data"] if tuple.has_key?("field_data")
      object[:TextTransformation] = tuple["text_transformation"]

      tuple_list << object
    end

    resource_name = "#{safe_name(name)}MatchSet#{type}"

    Resource(resource_name) do
      Type("AWS::WAF#{type}::SqlInjectionMatchSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("SqlInjectionMatchTuples", tuple_list)
    end
  end if defined? sql_injection_match_sets

  # Cross-site scripting match conditions
  xss_match_sets.each do |name, sets|
    tuple_list = []

    sets.each do |tuple|
      object = {}
      object[:FieldToMatch] = {}
      object[:FieldToMatch][:Type] = tuple["field_type"]
      object[:FieldToMatch][:Data] = tuple["field_data"] if tuple.has_key?("field_data")
      object[:TextTransformation] = tuple["text_transformation"]

      tuple_list << object
    end

    resource_name = "#{safe_name(name)}MatchSet#{type}"

    Resource("#{safe_name(name)}MatchSet#{type}") do
      Type("AWS::WAF#{type}::XssMatchSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("XssMatchTuples", tuple_list)
    end
  end if defined? xss_match_sets

  # Size constraint conditions
  size_constraint_sets.each do |name, sets|
    tuple_list = []

    sets.each do |tuple|
      object = {}
      object[:FieldToMatch] = {}
      object[:FieldToMatch][:Type] = tuple["field_type"]
      object[:FieldToMatch][:Data] = tuple["field_data"] if tuple.has_key?("field_data")
      object[:TextTransformation] = tuple["text_transformation"]
      object[:ComparisonOperator] = tuple["comparison_operator"]
      object[:Size] = tuple['size']

      tuple_list << object
    end

    resource_name = "#{safe_name(name)}Set#{type}"

    Resource(resource_name) do
      Type("AWS::WAF#{type}::SizeConstraintSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("SizeConstraints", tuple_list)
    end
  end if defined? size_constraint_sets

  # Byte match sets
  byte_match_sets.each do |name, sets|
    tuple_list = []

    sets.each do |tuple|
      object = {}
      object[:FieldToMatch] = {}
      object[:FieldToMatch][:Type] = tuple["field_type"]
      object[:FieldToMatch][:Data] = tuple["field_data"] if tuple.has_key?("field_data")
      object[:TextTransformation] = tuple["text_transformation"]
      object[:PositionalConstraint] = tuple["positional_constraint"]
      object[:TargetString] = tuple["target_string"]

      tuple_list << object
    end

    resource_name = "#{safe_name(name)}MatchSet#{type}"

    Resource(resource_name) do
      Type("AWS::WAF#{type}::ByteMatchSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("ByteMatchTuples", tuple_list)
    end
  end if defined? byte_match_sets

  # IP descriptor sets
  ip_sets.each do |name, sets|
    descriptor_list = []

    sets.each do |set|
      descriptor_list << {
        Type: set["type"] || "IPV4",
        Value: set["value"]
      }
    end

    resource_name = "#{safe_name(name)}IPSet#{type}"

    Resource(resource_name) do
      Type("AWS::WAF#{type}::IPSet")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("IPSetDescriptors", descriptor_list)
    end
  end if defined? ip_sets

  ## Create the Rules
  rules.each do |name, config|
    predicates = []

    config["predicates"].each do |predicate|
      condition = predicate["condition_name"]

      case predicate['type']
      when 'RegexMatch'
        data_id = FnGetAtt(safe_name(condition) + type, 'MatchID')  # A custom resource

      when 'ByteMatch', 'SqlInjectionMatch', 'XssMatch'
        data_id = Ref(safe_name(condition) + 'MatchSet' + type)

      when 'SizeConstraint'
        data_id = Ref(safe_name(condition) + 'Set' + type)

      when 'IPMatch'
        next if !defined?(ip_sets) or !ip_sets.key?(condition) # Allow an empty IP set
        data_id = Ref(safe_name(condition) + 'IPSet' + type)
      end

      predicates << {
          DataId: data_id,
          Negated: predicate["negated"],
          Type: predicate["type"]
        }
    end

    resource_name = "#{safe_name(name)}#{type}"

    Resource(resource_name) do
      Type("AWS::WAF#{type}::Rule")
      Property("Name", FnSub("${EnvironmentName}-#{name}"))
      Property("MetricName", FnJoin('', [safe_stack_name, safe_name(name)]))
      Property("Predicates",  predicates) if !predicates.empty?
    end

    Output(resource_name) do
      Value(Ref(resource_name))
      Export FnSub("${EnvironmentName}-#{resource_name}") if export_rules
    end

  end if defined? rules

  if defined? web_acl
    rules = []

    web_acl['rules'].each do |name, config|
      rules << {
        Action: { Type: config["action"] },
        Priority: config["priority"],
        RuleId: Ref(safe_name(name) + type)
      }
    end

    resource_name = "WebACL#{type}"

    Resource(resource_name) do
      Type("AWS::WAF#{type}::WebACL")
      Property("Name", FnSub("${EnvironmentName}-#{web_acl['name']}"))
      Property("MetricName", FnJoin('', [safe_stack_name, safe_name(web_acl['name'])]))
      Property("DefaultAction", { "Type" => web_acl['default_action'] })
      Property("Rules", rules)
    end

    Output(resource_name) do
      Value(Ref(resource_name))
      Export FnSub("${EnvironmentName}-#{web_acl['name']}-#{resource_name}") if export_acl
    end

    associations.each do |res_name, res_arn|
      Condition 'IsUseWAFv1'
      Resource("WebACLAssociation#{res_name}#{type}") do
        Type "AWS::WAFRegional::WebACLAssociation"
        Property("ResourceArn", Ref(res_arn))
        Property("WebACLId", Ref(resource_name))
      end
    end if defined?(associations)

    if type == 'Regional'
      Resource("WebACLAssociation") do
        Condition 'AssociateWithResource'
        Type "AWS::WAFRegional::WebACLAssociation"
        Property("ResourceArn", Ref("AssociatedResourceArn"))
        Property("WebACLId", Ref(resource_name))
      end
    end
  end

  if defined? custom_resource_rules
    custom_resource_rules.each do |name, config|

      resource_name = "#{safe_name(name)}RateBasedRule#{type}"

      if config['type'] == 'RateBasedRule'
        Resource(resource_name) {
          Type 'Custom::WAFRateLimit'
          Property('ServiceToken', FnGetAtt(config['function_name'], 'Arn'))
          Property('RuleName',  FnSub("${EnvironmentName}-#{name}"))
          Property('IpSetName', FnSub("${EnvironmentName}-#{name}-ip-set"))
          Property('Region',    Ref("AWS::Region"))
          Property('WebACLId',  Ref(config['web_acl_id']))
          Property('Rate',      config['rate'])
          Property('Negated',   config['negated'])
          Property('Action',    config['action'])
          Property('Priority',  config['priority'])
          Property('Regional',  config['regional'])
          Property('IPSet',     generate_waf_ip_set(cr_ip_sets, ['rate_limit'])) if defined?(cr_ip_sets)
        }

        Output(resource_name) do
          Value(FnGetAtt(resource_name, "RuleID"))
          Export FnSub("${EnvironmentName}-#{resource_name}") if export_rules
        end
      end
    end
  end
end
