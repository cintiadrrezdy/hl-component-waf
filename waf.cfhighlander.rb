CfhighlanderTemplate do

  Description "#{component_name} - #{component_version}"

  Parameters do
    ComponentParam 'EnvironmentName', 'dev', isGlobal: true
    ComponentParam 'EnvironmentType', 'development', isGlobal: true
    ComponentParam 'AssociatedResourceArn', ''

    # Web ACL associations
    associations.each do |res_name, res_arn|
      ComponentParam res_arn
    end if defined?(associations)
  end

  LambdaFunctions 'custom_resource_functions' if defined? custom_resource_functions

end
