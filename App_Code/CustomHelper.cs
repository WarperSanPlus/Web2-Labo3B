using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;
using System.Web;

// Auteur: Nicolas Chourot
namespace System.Web.Mvc
{
    public static class CustomHelper
    {
        private static string GetErrorMessage(ModelMetadata metadata)
        {
            string retVal = String.Empty;

            var customTypeDescriptor = new AssociatedMetadataTypeTypeDescriptionProvider(metadata.ContainerType).GetTypeDescriptor(metadata.ContainerType);
            if (customTypeDescriptor != null)
            {
                var descriptor = customTypeDescriptor.GetProperties().Find(metadata.PropertyName, true);
                var req = (new List<Attribute>(descriptor.Attributes.OfType<Attribute>())).OfType<RequiredAttribute>().FirstOrDefault();

                if (req != null)
                    retVal = req.ErrorMessage;
            }

            return retVal;
        }

        public static string GetDisplayName(this Enum value)
        {
            var type = value.GetType();
            if (!type.IsEnum) throw new ArgumentException(String.Format("Type '{0}' is not Enum", type));

            var members = type.GetMember(value.ToString());
            if (members.Length == 0) throw new ArgumentException(String.Format("Member '{0}' not found in type '{1}'", value, type.Name));

            var member = members[0];
            var attributes = member.GetCustomAttributes(typeof(DisplayAttribute), false);
            if (attributes.Length == 0) //throw new ArgumentException(String.Format("'{0}.{1}' doesn't have DisplayAttribute", type.Name, value));
                return member.Name;
            var attribute = (DisplayAttribute)attributes[0];
            return attribute.GetName();
        }

        public static MvcHtmlString RadioButtonsGroupFor<TModel, TValue>(
             this HtmlHelper<TModel> htmlHelper, // Extension definition for HtmlHelper class
             Expression<Func<TModel, TValue>> expression) // lambda expression signature
        {
            TagBuilder HTMLRadioButtonGroup = new TagBuilder("div");

            var metadata = ModelMetadata.FromLambdaExpression(expression, htmlHelper.ViewData);

            // we assume here that metadata.ModelType is an enumtype
            //var enumList = Enum.GetValues(metadata.ModelType);

            var enumList = Enum.GetValues(Nullable.GetUnderlyingType(metadata.ModelType) ?? metadata.ModelType);

            bool first = true;

            foreach (object enumObject in enumList)
            {
                TagBuilder div = new TagBuilder("div");

                TagBuilder label = new TagBuilder("label");
                label.AddCssClass("radio");

                TagBuilder radioButton = new TagBuilder("input");
                // Install client validation attributes
                if (first)
                {
                    radioButton.Attributes["data-val"] = "true";
                    radioButton.Attributes["data-val-required"] = GetErrorMessage(metadata);
                    first = false;
                }

                if (enumObject.ToString() == metadata.SimpleDisplayText)
                {
                    radioButton.Attributes["checked"] = "checked";
                }
                string enumDisplayName = GetDisplayName((Enum)enumObject);
                radioButton.Attributes["type"] = "radio";
                radioButton.Attributes["name"] = metadata.PropertyName;
                radioButton.Attributes["value"] = enumObject.ToString();

                label.InnerHtml += radioButton;
                label.InnerHtml += enumDisplayName;
                div.InnerHtml += label;


                HTMLRadioButtonGroup.InnerHtml += div;
            }
            return new MvcHtmlString(HTMLRadioButtonGroup.ToString());
        }
        public static MvcHtmlString RadioButtonsGroupFor<TModel, TValue>(
            this HtmlHelper<TModel> htmlHelper, // Extension definition for HtmlHelper class
            Expression<Func<TModel, TValue>> expression,
            SelectList choices) // lambda expression signature
        {
            TagBuilder HTMLRadioButtonGroup = new TagBuilder("div");

            var metadata = ModelMetadata.FromLambdaExpression(expression, htmlHelper.ViewData);

            // we assume here that metadata.ModelType is an enumtype
            //var enumList = Enum.GetValues(metadata.ModelType);

            bool first = true;

            foreach (SelectListItem choice in choices)
            {
                TagBuilder div = new TagBuilder("div");

                TagBuilder label = new TagBuilder("label");
                label.AddCssClass("radio");

                TagBuilder radioButton = new TagBuilder("input");
                // Install client validation attributes
                if (first)
                {
                    radioButton.Attributes["data-val"] = "true";
                    radioButton.Attributes["data-val-required"] = GetErrorMessage(metadata);
                    first = false;
                }

                if (choice.Selected)
                {
                    radioButton.Attributes["checked"] = "checked";
                }
                radioButton.Attributes["type"] = "radio";
                radioButton.Attributes["name"] = metadata.PropertyName;
                radioButton.Attributes["value"] = choice.Value;

                label.InnerHtml += radioButton;
                label.InnerHtml += choice.Text;
                div.InnerHtml += label;


                HTMLRadioButtonGroup.InnerHtml += div;
            }
            return new MvcHtmlString(HTMLRadioButtonGroup.ToString());
        }
    }
}