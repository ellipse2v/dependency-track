/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.resources.v1.misc;

import io.pebbletemplates.pebble.PebbleEngine;
import io.pebbletemplates.pebble.template.PebbleTemplate;
import org.dependencytrack.metrics.ProjectMetrics;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.util.HashMap;
import java.util.Map;

/**
 * Creates svg badges from various metrics for display on external sites.
 *
 * @author Steve Springett
 * @since 3.6.0
 */
public class Badger {

    private static final PebbleEngine ENGINE =
            new PebbleEngine.Builder().newLineTrimming(false).build();
    private static final PebbleTemplate PROJECT_VULNS_TEMPLATE =
            ENGINE.getTemplate("templates/badge/project-vulns.peb");
    private static final PebbleTemplate PROJECT_VULNS_NONE_TEMPLATE =
            ENGINE.getTemplate("templates/badge/project-vulns-none.peb");
    private static final PebbleTemplate PROJECT_VULNS_NO_METRICS_TEMPLATE =
            ENGINE.getTemplate("templates/badge/project-vulns-nometrics.peb");
    private static final PebbleTemplate PROJECT_VIOLATIONS_TEMPLATE =
            ENGINE.getTemplate("templates/badge/project-violations.peb");
    private static final PebbleTemplate PROJECT_VIOLATIONS_NONE_TEMPLATE =
            ENGINE.getTemplate("templates/badge/project-violations-none.peb");
    private static final PebbleTemplate PROJECT_VIOLATIONS_NO_METRICS_TEMPLATE =
            ENGINE.getTemplate("templates/badge/project-violations-nometrics.peb");
    private static final PebbleTemplate PROJECT_KEV_TEMPLATE = ENGINE.getTemplate("templates/badge/project-kev.peb");
    private static final String KEV_COLOR_PRESENT = "#dc0000";
    private static final String KEV_COLOR_NONE = "#4c1";
    private static final String KEV_COLOR_NO_METRICS = "#9f9f9f";

    public String generateVulnerabilities(ProjectMetrics metrics, String linkToProjectVuln) {
        final Map<String, Object> context = new HashMap<>();
        context.put("roundedPixels", "3");
        if (linkToProjectVuln != null && !linkToProjectVuln.isBlank()) {
            context.put("href", linkToProjectVuln);
        }
        if (metrics == null) {
            return writeSvg(PROJECT_VULNS_NO_METRICS_TEMPLATE, context);
        } else if (metrics.getVulnerabilities() > 0) {
            context.put("critical", String.valueOf(metrics.getCritical()));
            context.put("high", String.valueOf(metrics.getHigh()));
            context.put("medium", String.valueOf(metrics.getMedium()));
            context.put("low", String.valueOf(metrics.getLow()));
            context.put("unassigned", String.valueOf(metrics.getUnassigned()));
            return writeSvg(PROJECT_VULNS_TEMPLATE, context);
        } else {
            return writeSvg(PROJECT_VULNS_NONE_TEMPLATE, context);
        }
    }

    public String generateViolations(ProjectMetrics metrics, String linkToProjectViolations) {
        final Map<String, Object> context = new HashMap<>();
        context.put("roundedPixels", "3");
        if (linkToProjectViolations != null && !linkToProjectViolations.isBlank()) {
            context.put("href", linkToProjectViolations);
        }
        if (metrics == null) {
            return writeSvg(PROJECT_VIOLATIONS_NO_METRICS_TEMPLATE, context);
        } else if (metrics.getPolicyViolationsTotal() > 0) {
            context.put("fail", String.valueOf(metrics.getPolicyViolationsFail()));
            context.put("warn", String.valueOf(metrics.getPolicyViolationsWarn()));
            context.put("info", String.valueOf(metrics.getPolicyViolationsInfo()));
            return writeSvg(PROJECT_VIOLATIONS_TEMPLATE, context);
        } else {
            return writeSvg(PROJECT_VIOLATIONS_NONE_TEMPLATE, context);
        }
    }

    public String generateKev(ProjectMetrics metrics, String linkToProjectKevFindings) {
        final String value;
        final String color;
        if (metrics == null) {
            value = "no metrics";
            color = KEV_COLOR_NO_METRICS;
        } else if (metrics.getKev() > 0) {
            value = String.valueOf(metrics.getKev());
            color = KEV_COLOR_PRESENT;
        } else {
            value = "none";
            color = KEV_COLOR_NONE;
        }

        // Approximates the rendered width of 11px sans-serif text, plus padding.
        final int valueWidth = Math.max(20, value.length() * 7 + 12);

        final Map<String, Object> context = new HashMap<>();
        context.put("roundedPixels", "3");
        context.put("value", value);
        context.put("color", color);
        context.put("valueWidth", String.valueOf(valueWidth));
        context.put("width", String.valueOf(34 + valueWidth));
        if (linkToProjectKevFindings != null && !linkToProjectKevFindings.isBlank()) {
            context.put("href", linkToProjectKevFindings);
        }
        return writeSvg(PROJECT_KEV_TEMPLATE, context);
    }

    private String writeSvg(PebbleTemplate template, Map<String, Object> context) {
        try (Writer writer = new StringWriter()) {
            template.evaluate(writer, context);
            return writer.toString();
        } catch (IOException e) {
            LoggerFactory.getLogger(this.getClass()).error("An error was encountered evaluating template", e);
            return null;
        }
    }
}
